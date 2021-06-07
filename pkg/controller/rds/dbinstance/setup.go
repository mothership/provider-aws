package dbinstance

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	svcsdk "github.com/aws/aws-sdk-go/service/rds"
	svcsdkapi "github.com/aws/aws-sdk-go/service/rds/rdsiface"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/password"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	svcapitypes "github.com/crossplane/provider-aws/apis/rds/v1alpha1"
	aws "github.com/crossplane/provider-aws/pkg/clients"
	"github.com/crossplane/provider-aws/pkg/clients/rds"
)

// error constants
const (
	errGetSecretFailed    = "failed to get Kubernetes secret"
	errUpdateSecretFailed = "failed to update Kubernetes secret"
	errSaveSecretFailed   = "failed to save generated password to Kubernetes secret"
)

// time formats
const (
	maintenanceWindowFormat = "Mon:15:04"
	backupWindowFormat      = "15:04"
)

// SetupDBInstance adds a controller that reconciles DBInstance
func SetupDBInstance(mgr ctrl.Manager, l logging.Logger, rl workqueue.RateLimiter) error {
	name := managed.ControllerName(svcapitypes.DBInstanceGroupKind)
	opts := []option{
		func(e *external) {
			c := &custom{client: e.client, kube: e.kube}
			e.lateInitialize = lateInitializeHook
			e.isUpToDate = c.isUpToDate
			e.preObserve = preObserve
			e.postObserve = postObserve
			e.preCreate = c.preCreate
			e.postCreate = c.postCreate
			e.preDelete = preDelete
			e.filterList = filterList
			e.preUpdate = preUpdate
		},
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(controller.Options{
			RateLimiter: ratelimiter.NewDefaultManagedRateLimiter(rl),
		}).
		For(&svcapitypes.DBInstance{}).
		Complete(managed.NewReconciler(mgr,
			resource.ManagedKind(svcapitypes.DBInstanceGroupVersionKind),
			managed.WithExternalConnecter(&connector{kube: mgr.GetClient(), opts: opts}),
			managed.WithLogger(l.WithValues("controller", name)),
			managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name)))))
}

type custom struct {
	kube   client.Client
	client svcsdkapi.RDSAPI
}

func preObserve(_ context.Context, cr *svcapitypes.DBInstance, obj *svcsdk.DescribeDBInstancesInput) error {
	obj.DBInstanceIdentifier = aws.String(meta.GetExternalName(cr))
	return nil
}

func (e *custom) preCreate(ctx context.Context, cr *svcapitypes.DBInstance, obj *svcsdk.CreateDBInstanceInput) error {
	pw, _, err := rds.GetPassword(ctx, e.kube, cr.Spec.ForProvider.MasterUserPasswordSecretRef, cr.Spec.WriteConnectionSecretToReference)
	if resource.IgnoreNotFound(err) != nil {
		return errors.Wrap(err, "cannot get password from the given secret")
	}
	if pw == "" && cr.Spec.ForProvider.AutogeneratePassword {
		pw, err = password.Generate()
		if err != nil {
			return errors.Wrap(err, "unable to generate a password")
		}
		if err := e.savePasswordSecret(ctx, cr, pw); err != nil {
			return errors.Wrap(err, errSaveSecretFailed)
		}
	}
	obj.MasterUserPassword = aws.String(pw)
	obj.DBInstanceIdentifier = aws.String(meta.GetExternalName(cr))
	if len(cr.Spec.ForProvider.VPCSecurityGroupIDs) > 0 {
		obj.VpcSecurityGroupIds = make([]*string, len(cr.Spec.ForProvider.VPCSecurityGroupIDs))
		for i, v := range cr.Spec.ForProvider.VPCSecurityGroupIDs {
			obj.VpcSecurityGroupIds[i] = aws.String(v)
		}
	}
	if len(cr.Spec.ForProvider.DBSecurityGroups) > 0 {
		obj.DBSecurityGroups = make([]*string, len(cr.Spec.ForProvider.DBSecurityGroups))
		for i, v := range cr.Spec.ForProvider.DBSecurityGroups {
			obj.DBSecurityGroups[i] = aws.String(v)
		}
	}
	return nil
}

func (e *custom) postCreate(ctx context.Context, cr *svcapitypes.DBInstance, _ *svcsdk.CreateDBInstanceOutput, _ managed.ExternalCreation, err error) (managed.ExternalCreation, error) {
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	conn := managed.ConnectionDetails{
		xpv1.ResourceCredentialsSecretUserKey: []byte(aws.StringValue(cr.Spec.ForProvider.MasterUsername)),
	}
	pw, _, err := rds.GetPassword(ctx, e.kube, cr.Spec.ForProvider.MasterUserPasswordSecretRef, cr.Spec.WriteConnectionSecretToReference)
	if resource.IgnoreNotFound(err) != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "cannot get password from the given secret")
	}
	if pw != "" {
		conn[xpv1.ResourceCredentialsSecretPasswordKey] = []byte(pw)
	}
	return managed.ExternalCreation{
		ConnectionDetails: conn,
	}, nil
}

func preUpdate(_ context.Context, cr *svcapitypes.DBInstance, obj *svcsdk.ModifyDBInstanceInput) error {
	obj.DBInstanceIdentifier = aws.String(meta.GetExternalName(cr))
	return nil
}

func preDelete(_ context.Context, cr *svcapitypes.DBInstance, obj *svcsdk.DeleteDBInstanceInput) (bool, error) {
	obj.DBInstanceIdentifier = aws.String(meta.GetExternalName(cr))
	obj.FinalDBSnapshotIdentifier = aws.String(cr.Spec.ForProvider.FinalDBSnapshotIdentifier)
	obj.SkipFinalSnapshot = aws.Bool(cr.Spec.ForProvider.SkipFinalSnapshot)
	return false, nil
}

func postObserve(_ context.Context, cr *svcapitypes.DBInstance, resp *svcsdk.DescribeDBInstancesOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	switch aws.StringValue(resp.DBInstances[0].DBInstanceStatus) {
	case "available":
		cr.SetConditions(xpv1.Available())
	case "deleting", "stopped", "stopping":
		cr.SetConditions(xpv1.Unavailable())
	case "creating":
		cr.SetConditions(xpv1.Creating())
	}
	return obs, nil
}

func lateInitializeHook(in *svcapitypes.DBInstanceParameters, out *svcsdk.DescribeDBInstancesOutput) error {
	if len(out.DBInstances) == 0 {
		return errors.New("no DBInstance in DescribeDBInstancesOutput, can not lateIntitialize")
	}
	return lateInitialize(in, out.DBInstances[0])
}

func lateInitialize(in *svcapitypes.DBInstanceParameters, db *svcsdk.DBInstance) error { // nolint:gocyclo
	in.DBInstanceClass = aws.LateInitializeStringPtr(in.DBInstanceClass, db.DBInstanceClass)
	in.Engine = aws.LateInitializeStringPtr(in.Engine, db.Engine)

	in.AllocatedStorage = aws.LateInitializeInt64Ptr(in.AllocatedStorage, db.AllocatedStorage)
	in.AutoMinorVersionUpgrade = aws.LateInitializeBoolPtr(in.AutoMinorVersionUpgrade, db.AutoMinorVersionUpgrade)
	in.AvailabilityZone = aws.LateInitializeStringPtr(in.AvailabilityZone, db.AvailabilityZone)
	in.BackupRetentionPeriod = aws.LateInitializeInt64Ptr(in.BackupRetentionPeriod, db.BackupRetentionPeriod)
	in.CharacterSetName = aws.LateInitializeStringPtr(in.CharacterSetName, db.CharacterSetName)
	in.CopyTagsToSnapshot = aws.LateInitializeBoolPtr(in.CopyTagsToSnapshot, db.CopyTagsToSnapshot)
	in.DBClusterIdentifier = aws.LateInitializeStringPtr(in.DBClusterIdentifier, db.DBClusterIdentifier)
	in.DBName = aws.LateInitializeStringPtr(in.DBName, db.DBName)
	in.DeletionProtection = aws.LateInitializeBoolPtr(in.DeletionProtection, db.DeletionProtection)
	in.EnableIAMDatabaseAuthentication = aws.LateInitializeBoolPtr(in.EnableIAMDatabaseAuthentication, db.IAMDatabaseAuthenticationEnabled)
	in.EnablePerformanceInsights = aws.LateInitializeBoolPtr(in.EnablePerformanceInsights, db.PerformanceInsightsEnabled)
	in.IOPS = aws.LateInitializeInt64Ptr(in.IOPS, db.Iops)
	in.KMSKeyID = aws.LateInitializeStringPtr(in.KMSKeyID, db.KmsKeyId)
	in.LicenseModel = aws.LateInitializeStringPtr(in.LicenseModel, db.LicenseModel)
	in.MasterUsername = aws.LateInitializeStringPtr(in.MasterUsername, db.MasterUsername)
	in.MonitoringInterval = aws.LateInitializeInt64Ptr(in.MonitoringInterval, db.MonitoringInterval)
	in.MonitoringRoleARN = aws.LateInitializeStringPtr(in.MonitoringRoleARN, db.MonitoringRoleArn)
	in.MultiAZ = aws.LateInitializeBoolPtr(in.MultiAZ, db.MultiAZ)
	in.PerformanceInsightsKMSKeyID = aws.LateInitializeStringPtr(in.PerformanceInsightsKMSKeyID, db.PerformanceInsightsKMSKeyId)
	in.PerformanceInsightsRetentionPeriod = aws.LateInitializeInt64Ptr(in.PerformanceInsightsRetentionPeriod, db.PerformanceInsightsRetentionPeriod)
	in.PreferredBackupWindow = aws.LateInitializeStringPtr(in.PreferredBackupWindow, db.PreferredBackupWindow)
	in.PreferredMaintenanceWindow = aws.LateInitializeStringPtr(in.PreferredMaintenanceWindow, db.PreferredMaintenanceWindow)
	in.PromotionTier = aws.LateInitializeInt64Ptr(in.PromotionTier, db.PromotionTier)
	in.PubliclyAccessible = aws.LateInitializeBoolPtr(in.PubliclyAccessible, db.PubliclyAccessible)
	in.StorageEncrypted = aws.LateInitializeBoolPtr(in.StorageEncrypted, db.StorageEncrypted)
	in.StorageType = aws.LateInitializeStringPtr(in.StorageType, db.StorageType)
	in.Timezone = aws.LateInitializeStringPtr(in.Timezone, db.Timezone)

	if db.Endpoint != nil {
		in.Port = aws.LateInitializeInt64Ptr(in.Port, db.Endpoint.Port)
	}

	if len(in.DBSecurityGroups) == 0 && len(db.DBSecurityGroups) != 0 {
		in.DBSecurityGroups = make([]string, len(db.DBSecurityGroups))
		for i, val := range db.DBSecurityGroups {
			in.DBSecurityGroups[i] = aws.StringValue(val.DBSecurityGroupName)
		}
	}
	if aws.StringValue(in.DBSubnetGroupName) == "" && db.DBSubnetGroup != nil {
		in.DBSubnetGroupName = db.DBSubnetGroup.DBSubnetGroupName
	}
	if len(in.EnableCloudwatchLogsExports) == 0 && len(db.EnabledCloudwatchLogsExports) != 0 {
		in.EnableCloudwatchLogsExports = db.EnabledCloudwatchLogsExports
	}
	if len(in.ProcessorFeatures) == 0 && len(db.ProcessorFeatures) != 0 {
		in.ProcessorFeatures = make([]*svcapitypes.ProcessorFeature, len(db.ProcessorFeatures))
		for i, val := range db.ProcessorFeatures {
			in.ProcessorFeatures[i] = &svcapitypes.ProcessorFeature{
				Name:  val.Name,
				Value: val.Value,
			}
		}
	}
	if len(in.VPCSecurityGroupIDs) == 0 && len(db.VpcSecurityGroups) != 0 {
		in.VPCSecurityGroupIDs = make([]string, len(db.VpcSecurityGroups))
		for i, val := range db.VpcSecurityGroups {
			in.VPCSecurityGroupIDs[i] = aws.StringValue(val.VpcSecurityGroupId)
		}
	}
	in.EngineVersion = aws.LateInitializeStringPtr(in.EngineVersion, db.EngineVersion)
	// When version 5.6 is chosen, AWS creates 5.6.41 and that's totally valid.
	// But we detect as if we need to update it all the time. Here, we assign
	// the actual full version to our spec to avoid unnecessary update signals.
	if strings.HasPrefix(aws.StringValue(db.EngineVersion), aws.StringValue(in.EngineVersion)) {
		in.EngineVersion = db.EngineVersion
	}
	if in.DBParameterGroupName == nil {
		for i := range db.DBParameterGroups {
			if db.DBParameterGroups[i].DBParameterGroupName != nil {
				in.DBParameterGroupName = db.DBParameterGroups[i].DBParameterGroupName
				break
			}
		}
	}

	return nil
}

func (e *custom) isUpToDate(cr *svcapitypes.DBInstance, out *svcsdk.DescribeDBInstancesOutput) (bool, error) {
	// (PocketMobsters): because we don't have a context here, we cannot check
	// if the password has changed or not unless we create a new context.
	// for now we're not doing so
	if len(out.DBInstances) == 0 {
		return false, errors.New("no DBInstance in DescribeDBInstancesOutput")
	}
	db := out.DBInstances[0]
	patch, err := createPatch(db, &cr.Spec.ForProvider)
	if err != nil {
		return false, err
	}

	// (PocketMobsters): AWS reformats our preferred time windows for backups and maintenance
	// so we can't rely on automatic equality checks for them
	maintenanceWindowChanged, err := compareTimeRanges(maintenanceWindowFormat, cr.Spec.ForProvider.PreferredMaintenanceWindow, db.PreferredMaintenanceWindow)
	if err != nil {
		return false, err
	}
	backupWindowChanged, err := compareTimeRanges(backupWindowFormat, cr.Spec.ForProvider.PreferredBackupWindow, db.PreferredBackupWindow)
	if err != nil {
		return false, err
	}

	return cmp.Equal(&svcapitypes.DBInstanceParameters{}, patch, cmpopts.EquateEmpty(),
		cmpopts.IgnoreTypes(&xpv1.Reference{}, &xpv1.Selector{}, []xpv1.Reference{}),
		cmpopts.IgnoreFields(svcapitypes.DBInstanceParameters{}, "Region"),
		cmpopts.IgnoreFields(svcapitypes.DBInstanceParameters{}, "Tags"),
		cmpopts.IgnoreFields(svcapitypes.DBInstanceParameters{}, "SkipFinalSnapshot"),
		cmpopts.IgnoreFields(svcapitypes.DBInstanceParameters{}, "FinalDBSnapshotIdentifier"),
		cmpopts.IgnoreFields(svcapitypes.DBInstanceParameters{}, "MasterUserPasswordSecretRef"),
		cmpopts.IgnoreFields(svcapitypes.DBInstanceParameters{}, "AutogeneratePassword"),
		cmpopts.IgnoreFields(svcapitypes.DBInstanceParameters{}, "PreferredMaintenanceWindow"),
		cmpopts.IgnoreFields(svcapitypes.DBInstanceParameters{}, "PreferredBackupWindow"),
	) && !maintenanceWindowChanged && !backupWindowChanged, nil
}

func createPatch(in *svcsdk.DBInstance, target *svcapitypes.DBInstanceParameters) (*svcapitypes.DBInstanceParameters, error) {
	currentParams := &svcapitypes.DBInstanceParameters{}
	err := lateInitialize(currentParams, in)
	if err != nil {
		return nil, err
	}
	jsonPatch, err := aws.CreateJSONPatch(currentParams, target)
	if err != nil {
		return nil, err
	}
	patch := &svcapitypes.DBInstanceParameters{}
	if err := json.Unmarshal(jsonPatch, patch); err != nil {
		return nil, err
	}
	return patch, nil
}

func compareTimeRanges(format string, expectedWindow *string, actualWindow *string) (bool, error) {
	if aws.StringValue(expectedWindow) == "" {
		// no window to set, don't bother
		return false, nil
	}
	if aws.StringValue(actualWindow) == "" {
		// expected is set but actual is not, so we should set it
		return true, nil
	}
	// all windows here have a "-" in between two values in the expected format, so just split
	leftSpans := strings.Split(*expectedWindow, "-")
	rightSpans := strings.Split(*actualWindow, "-")
	for i, _ := range leftSpans {
		left, err := time.Parse(format, leftSpans[i])
		if err != nil {
			return false, err
		}
		right, err := time.Parse(format, rightSpans[i])
		if err != nil {
			return false, err
		}
		if left != right {
			return true, nil
		}
	}
	return false, nil
}

func filterList(cr *svcapitypes.DBInstance, obj *svcsdk.DescribeDBInstancesOutput) *svcsdk.DescribeDBInstancesOutput {
	resp := &svcsdk.DescribeDBInstancesOutput{}
	for _, dbInstance := range obj.DBInstances {
		if aws.StringValue(dbInstance.DBInstanceIdentifier) == meta.GetExternalName(cr) {
			resp.DBInstances = append(resp.DBInstances, dbInstance)
			break
		}
	}
	return resp
}

func (e *custom) savePasswordSecret(ctx context.Context, cr *svcapitypes.DBInstance, pw string) error {
	if cr.Spec.ForProvider.MasterUserPasswordSecretRef == nil {
		return errors.New("no MasterUserPasswordSecretRef given, unable to save password")
	}
	ref := cr.Spec.ForProvider.MasterUserPasswordSecretRef
	nn := types.NamespacedName{
		Name:      ref.Name,
		Namespace: ref.Namespace,
	}
	sc := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nn.Name,
			Namespace: nn.Namespace,
		},
	}
	err := e.kube.Get(ctx, nn, sc)
	var create bool
	// if there was an error not related to the output secret not existing we should exit
	if resource.IgnoreNotFound(err) != nil {
		return errors.Wrap(err, errGetSecretFailed)
	}
	// but if it didn't exist, we should create instead of update
	if err != nil {
		create = true
	}
	sc.StringData = map[string]string{
		ref.Key: pw,
	}
	if create {
		err = e.kube.Create(ctx, sc, &client.CreateOptions{})
	} else {
		err = e.kube.Update(ctx, sc, &client.UpdateOptions{})
	}
	if err != nil {
		return errors.Wrap(err, errUpdateSecretFailed)
	}
	return nil
}
