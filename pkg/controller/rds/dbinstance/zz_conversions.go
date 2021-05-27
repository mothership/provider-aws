/*
Copyright 2021 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by ack-generate. DO NOT EDIT.

package dbinstance

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/rds"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	svcapitypes "github.com/crossplane/provider-aws/apis/rds/v1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.

// GenerateDescribeDBInstancesInput returns input for read
// operation.
func GenerateDescribeDBInstancesInput(cr *svcapitypes.DBInstance) *svcsdk.DescribeDBInstancesInput {
	res := &svcsdk.DescribeDBInstancesInput{}

	if cr.Status.AtProvider.DBInstanceIdentifier != nil {
		res.SetDBInstanceIdentifier(*cr.Status.AtProvider.DBInstanceIdentifier)
	}

	return res
}

// GenerateDBInstance returns the current state in the form of *svcapitypes.DBInstance.
func GenerateDBInstance(resp *svcsdk.DescribeDBInstancesOutput) *svcapitypes.DBInstance {
	cr := &svcapitypes.DBInstance{}

	found := false
	for _, elem := range resp.DBInstances {
		if elem.AllocatedStorage != nil {
			cr.Spec.ForProvider.AllocatedStorage = elem.AllocatedStorage
		} else {
			cr.Spec.ForProvider.AllocatedStorage = nil
		}
		if elem.AssociatedRoles != nil {
			f1 := []*svcapitypes.DBInstanceRole{}
			for _, f1iter := range elem.AssociatedRoles {
				f1elem := &svcapitypes.DBInstanceRole{}
				if f1iter.FeatureName != nil {
					f1elem.FeatureName = f1iter.FeatureName
				}
				if f1iter.RoleArn != nil {
					f1elem.RoleARN = f1iter.RoleArn
				}
				if f1iter.Status != nil {
					f1elem.Status = f1iter.Status
				}
				f1 = append(f1, f1elem)
			}
			cr.Status.AtProvider.AssociatedRoles = f1
		} else {
			cr.Status.AtProvider.AssociatedRoles = nil
		}
		if elem.AutoMinorVersionUpgrade != nil {
			cr.Spec.ForProvider.AutoMinorVersionUpgrade = elem.AutoMinorVersionUpgrade
		} else {
			cr.Spec.ForProvider.AutoMinorVersionUpgrade = nil
		}
		if elem.AvailabilityZone != nil {
			cr.Spec.ForProvider.AvailabilityZone = elem.AvailabilityZone
		} else {
			cr.Spec.ForProvider.AvailabilityZone = nil
		}
		if elem.BackupRetentionPeriod != nil {
			cr.Spec.ForProvider.BackupRetentionPeriod = elem.BackupRetentionPeriod
		} else {
			cr.Spec.ForProvider.BackupRetentionPeriod = nil
		}
		if elem.CACertificateIdentifier != nil {
			cr.Status.AtProvider.CACertificateIdentifier = elem.CACertificateIdentifier
		} else {
			cr.Status.AtProvider.CACertificateIdentifier = nil
		}
		if elem.CharacterSetName != nil {
			cr.Spec.ForProvider.CharacterSetName = elem.CharacterSetName
		} else {
			cr.Spec.ForProvider.CharacterSetName = nil
		}
		if elem.CopyTagsToSnapshot != nil {
			cr.Spec.ForProvider.CopyTagsToSnapshot = elem.CopyTagsToSnapshot
		} else {
			cr.Spec.ForProvider.CopyTagsToSnapshot = nil
		}
		if elem.CustomerOwnedIpEnabled != nil {
			cr.Status.AtProvider.CustomerOwnedIPEnabled = elem.CustomerOwnedIpEnabled
		} else {
			cr.Status.AtProvider.CustomerOwnedIPEnabled = nil
		}
		if elem.DBClusterIdentifier != nil {
			cr.Spec.ForProvider.DBClusterIdentifier = elem.DBClusterIdentifier
		} else {
			cr.Spec.ForProvider.DBClusterIdentifier = nil
		}
		if elem.DBInstanceArn != nil {
			cr.Status.AtProvider.DBInstanceARN = elem.DBInstanceArn
		} else {
			cr.Status.AtProvider.DBInstanceARN = nil
		}
		if elem.DBInstanceAutomatedBackupsReplications != nil {
			f11 := []*svcapitypes.DBInstanceAutomatedBackupsReplication{}
			for _, f11iter := range elem.DBInstanceAutomatedBackupsReplications {
				f11elem := &svcapitypes.DBInstanceAutomatedBackupsReplication{}
				if f11iter.DBInstanceAutomatedBackupsArn != nil {
					f11elem.DBInstanceAutomatedBackupsARN = f11iter.DBInstanceAutomatedBackupsArn
				}
				f11 = append(f11, f11elem)
			}
			cr.Status.AtProvider.DBInstanceAutomatedBackupsReplications = f11
		} else {
			cr.Status.AtProvider.DBInstanceAutomatedBackupsReplications = nil
		}
		if elem.DBInstanceClass != nil {
			cr.Spec.ForProvider.DBInstanceClass = elem.DBInstanceClass
		} else {
			cr.Spec.ForProvider.DBInstanceClass = nil
		}
		if elem.DBInstanceIdentifier != nil {
			cr.Status.AtProvider.DBInstanceIdentifier = elem.DBInstanceIdentifier
		} else {
			cr.Status.AtProvider.DBInstanceIdentifier = nil
		}
		if elem.DBInstanceStatus != nil {
			cr.Status.AtProvider.DBInstanceStatus = elem.DBInstanceStatus
		} else {
			cr.Status.AtProvider.DBInstanceStatus = nil
		}
		if elem.DBName != nil {
			cr.Spec.ForProvider.DBName = elem.DBName
		} else {
			cr.Spec.ForProvider.DBName = nil
		}
		if elem.DBParameterGroups != nil {
			f16 := []*svcapitypes.DBParameterGroupStatus_SDK{}
			for _, f16iter := range elem.DBParameterGroups {
				f16elem := &svcapitypes.DBParameterGroupStatus_SDK{}
				if f16iter.DBParameterGroupName != nil {
					f16elem.DBParameterGroupName = f16iter.DBParameterGroupName
				}
				if f16iter.ParameterApplyStatus != nil {
					f16elem.ParameterApplyStatus = f16iter.ParameterApplyStatus
				}
				f16 = append(f16, f16elem)
			}
			cr.Status.AtProvider.DBParameterGroups = f16
		} else {
			cr.Status.AtProvider.DBParameterGroups = nil
		}
		if elem.DBSecurityGroups != nil {
			f17 := []*svcapitypes.DBSecurityGroupMembership{}
			for _, f17iter := range elem.DBSecurityGroups {
				f17elem := &svcapitypes.DBSecurityGroupMembership{}
				if f17iter.DBSecurityGroupName != nil {
					f17elem.DBSecurityGroupName = f17iter.DBSecurityGroupName
				}
				if f17iter.Status != nil {
					f17elem.Status = f17iter.Status
				}
				f17 = append(f17, f17elem)
			}
			cr.Status.AtProvider.DBSecurityGroups = f17
		} else {
			cr.Status.AtProvider.DBSecurityGroups = nil
		}
		if elem.DBSubnetGroup != nil {
			f18 := &svcapitypes.DBSubnetGroup{}
			if elem.DBSubnetGroup.DBSubnetGroupArn != nil {
				f18.DBSubnetGroupARN = elem.DBSubnetGroup.DBSubnetGroupArn
			}
			if elem.DBSubnetGroup.DBSubnetGroupDescription != nil {
				f18.DBSubnetGroupDescription = elem.DBSubnetGroup.DBSubnetGroupDescription
			}
			if elem.DBSubnetGroup.DBSubnetGroupName != nil {
				f18.DBSubnetGroupName = elem.DBSubnetGroup.DBSubnetGroupName
			}
			if elem.DBSubnetGroup.SubnetGroupStatus != nil {
				f18.SubnetGroupStatus = elem.DBSubnetGroup.SubnetGroupStatus
			}
			if elem.DBSubnetGroup.Subnets != nil {
				f18f4 := []*svcapitypes.Subnet{}
				for _, f18f4iter := range elem.DBSubnetGroup.Subnets {
					f18f4elem := &svcapitypes.Subnet{}
					if f18f4iter.SubnetAvailabilityZone != nil {
						f18f4elemf0 := &svcapitypes.AvailabilityZone{}
						if f18f4iter.SubnetAvailabilityZone.Name != nil {
							f18f4elemf0.Name = f18f4iter.SubnetAvailabilityZone.Name
						}
						f18f4elem.SubnetAvailabilityZone = f18f4elemf0
					}
					if f18f4iter.SubnetIdentifier != nil {
						f18f4elem.SubnetIdentifier = f18f4iter.SubnetIdentifier
					}
					if f18f4iter.SubnetOutpost != nil {
						f18f4elemf2 := &svcapitypes.Outpost{}
						if f18f4iter.SubnetOutpost.Arn != nil {
							f18f4elemf2.ARN = f18f4iter.SubnetOutpost.Arn
						}
						f18f4elem.SubnetOutpost = f18f4elemf2
					}
					if f18f4iter.SubnetStatus != nil {
						f18f4elem.SubnetStatus = f18f4iter.SubnetStatus
					}
					f18f4 = append(f18f4, f18f4elem)
				}
				f18.Subnets = f18f4
			}
			if elem.DBSubnetGroup.VpcId != nil {
				f18.VPCID = elem.DBSubnetGroup.VpcId
			}
			cr.Status.AtProvider.DBSubnetGroup = f18
		} else {
			cr.Status.AtProvider.DBSubnetGroup = nil
		}
		if elem.DbInstancePort != nil {
			cr.Status.AtProvider.DBInstancePort = elem.DbInstancePort
		} else {
			cr.Status.AtProvider.DBInstancePort = nil
		}
		if elem.DbiResourceId != nil {
			cr.Status.AtProvider.DBIResourceID = elem.DbiResourceId
		} else {
			cr.Status.AtProvider.DBIResourceID = nil
		}
		if elem.DeletionProtection != nil {
			cr.Spec.ForProvider.DeletionProtection = elem.DeletionProtection
		} else {
			cr.Spec.ForProvider.DeletionProtection = nil
		}
		if elem.DomainMemberships != nil {
			f22 := []*svcapitypes.DomainMembership{}
			for _, f22iter := range elem.DomainMemberships {
				f22elem := &svcapitypes.DomainMembership{}
				if f22iter.Domain != nil {
					f22elem.Domain = f22iter.Domain
				}
				if f22iter.FQDN != nil {
					f22elem.FQDN = f22iter.FQDN
				}
				if f22iter.IAMRoleName != nil {
					f22elem.IAMRoleName = f22iter.IAMRoleName
				}
				if f22iter.Status != nil {
					f22elem.Status = f22iter.Status
				}
				f22 = append(f22, f22elem)
			}
			cr.Status.AtProvider.DomainMemberships = f22
		} else {
			cr.Status.AtProvider.DomainMemberships = nil
		}
		if elem.EnabledCloudwatchLogsExports != nil {
			f23 := []*string{}
			for _, f23iter := range elem.EnabledCloudwatchLogsExports {
				var f23elem string
				f23elem = *f23iter
				f23 = append(f23, &f23elem)
			}
			cr.Status.AtProvider.EnabledCloudwatchLogsExports = f23
		} else {
			cr.Status.AtProvider.EnabledCloudwatchLogsExports = nil
		}
		if elem.Endpoint != nil {
			f24 := &svcapitypes.Endpoint{}
			if elem.Endpoint.Address != nil {
				f24.Address = elem.Endpoint.Address
			}
			if elem.Endpoint.HostedZoneId != nil {
				f24.HostedZoneID = elem.Endpoint.HostedZoneId
			}
			if elem.Endpoint.Port != nil {
				f24.Port = elem.Endpoint.Port
			}
			cr.Status.AtProvider.Endpoint = f24
		} else {
			cr.Status.AtProvider.Endpoint = nil
		}
		if elem.Engine != nil {
			cr.Spec.ForProvider.Engine = elem.Engine
		} else {
			cr.Spec.ForProvider.Engine = nil
		}
		if elem.EngineVersion != nil {
			cr.Spec.ForProvider.EngineVersion = elem.EngineVersion
		} else {
			cr.Spec.ForProvider.EngineVersion = nil
		}
		if elem.EnhancedMonitoringResourceArn != nil {
			cr.Status.AtProvider.EnhancedMonitoringResourceARN = elem.EnhancedMonitoringResourceArn
		} else {
			cr.Status.AtProvider.EnhancedMonitoringResourceARN = nil
		}
		if elem.IAMDatabaseAuthenticationEnabled != nil {
			cr.Status.AtProvider.IAMDatabaseAuthenticationEnabled = elem.IAMDatabaseAuthenticationEnabled
		} else {
			cr.Status.AtProvider.IAMDatabaseAuthenticationEnabled = nil
		}
		if elem.InstanceCreateTime != nil {
			cr.Status.AtProvider.InstanceCreateTime = &metav1.Time{*elem.InstanceCreateTime}
		} else {
			cr.Status.AtProvider.InstanceCreateTime = nil
		}
		if elem.Iops != nil {
			cr.Spec.ForProvider.IOPS = elem.Iops
		} else {
			cr.Spec.ForProvider.IOPS = nil
		}
		if elem.KmsKeyId != nil {
			cr.Spec.ForProvider.KMSKeyID = elem.KmsKeyId
		} else {
			cr.Spec.ForProvider.KMSKeyID = nil
		}
		if elem.LatestRestorableTime != nil {
			cr.Status.AtProvider.LatestRestorableTime = &metav1.Time{*elem.LatestRestorableTime}
		} else {
			cr.Status.AtProvider.LatestRestorableTime = nil
		}
		if elem.LicenseModel != nil {
			cr.Spec.ForProvider.LicenseModel = elem.LicenseModel
		} else {
			cr.Spec.ForProvider.LicenseModel = nil
		}
		if elem.ListenerEndpoint != nil {
			f34 := &svcapitypes.Endpoint{}
			if elem.ListenerEndpoint.Address != nil {
				f34.Address = elem.ListenerEndpoint.Address
			}
			if elem.ListenerEndpoint.HostedZoneId != nil {
				f34.HostedZoneID = elem.ListenerEndpoint.HostedZoneId
			}
			if elem.ListenerEndpoint.Port != nil {
				f34.Port = elem.ListenerEndpoint.Port
			}
			cr.Status.AtProvider.ListenerEndpoint = f34
		} else {
			cr.Status.AtProvider.ListenerEndpoint = nil
		}
		if elem.MasterUsername != nil {
			cr.Spec.ForProvider.MasterUsername = elem.MasterUsername
		} else {
			cr.Spec.ForProvider.MasterUsername = nil
		}
		if elem.MaxAllocatedStorage != nil {
			cr.Spec.ForProvider.MaxAllocatedStorage = elem.MaxAllocatedStorage
		} else {
			cr.Spec.ForProvider.MaxAllocatedStorage = nil
		}
		if elem.MonitoringInterval != nil {
			cr.Spec.ForProvider.MonitoringInterval = elem.MonitoringInterval
		} else {
			cr.Spec.ForProvider.MonitoringInterval = nil
		}
		if elem.MonitoringRoleArn != nil {
			cr.Spec.ForProvider.MonitoringRoleARN = elem.MonitoringRoleArn
		} else {
			cr.Spec.ForProvider.MonitoringRoleARN = nil
		}
		if elem.MultiAZ != nil {
			cr.Spec.ForProvider.MultiAZ = elem.MultiAZ
		} else {
			cr.Spec.ForProvider.MultiAZ = nil
		}
		if elem.NcharCharacterSetName != nil {
			cr.Spec.ForProvider.NcharCharacterSetName = elem.NcharCharacterSetName
		} else {
			cr.Spec.ForProvider.NcharCharacterSetName = nil
		}
		if elem.OptionGroupMemberships != nil {
			f41 := []*svcapitypes.OptionGroupMembership{}
			for _, f41iter := range elem.OptionGroupMemberships {
				f41elem := &svcapitypes.OptionGroupMembership{}
				if f41iter.OptionGroupName != nil {
					f41elem.OptionGroupName = f41iter.OptionGroupName
				}
				if f41iter.Status != nil {
					f41elem.Status = f41iter.Status
				}
				f41 = append(f41, f41elem)
			}
			cr.Status.AtProvider.OptionGroupMemberships = f41
		} else {
			cr.Status.AtProvider.OptionGroupMemberships = nil
		}
		if elem.PendingModifiedValues != nil {
			f42 := &svcapitypes.PendingModifiedValues{}
			if elem.PendingModifiedValues.AllocatedStorage != nil {
				f42.AllocatedStorage = elem.PendingModifiedValues.AllocatedStorage
			}
			if elem.PendingModifiedValues.BackupRetentionPeriod != nil {
				f42.BackupRetentionPeriod = elem.PendingModifiedValues.BackupRetentionPeriod
			}
			if elem.PendingModifiedValues.CACertificateIdentifier != nil {
				f42.CACertificateIdentifier = elem.PendingModifiedValues.CACertificateIdentifier
			}
			if elem.PendingModifiedValues.DBInstanceClass != nil {
				f42.DBInstanceClass = elem.PendingModifiedValues.DBInstanceClass
			}
			if elem.PendingModifiedValues.DBInstanceIdentifier != nil {
				f42.DBInstanceIdentifier = elem.PendingModifiedValues.DBInstanceIdentifier
			}
			if elem.PendingModifiedValues.DBSubnetGroupName != nil {
				f42.DBSubnetGroupName = elem.PendingModifiedValues.DBSubnetGroupName
			}
			if elem.PendingModifiedValues.EngineVersion != nil {
				f42.EngineVersion = elem.PendingModifiedValues.EngineVersion
			}
			if elem.PendingModifiedValues.IAMDatabaseAuthenticationEnabled != nil {
				f42.IAMDatabaseAuthenticationEnabled = elem.PendingModifiedValues.IAMDatabaseAuthenticationEnabled
			}
			if elem.PendingModifiedValues.Iops != nil {
				f42.IOPS = elem.PendingModifiedValues.Iops
			}
			if elem.PendingModifiedValues.LicenseModel != nil {
				f42.LicenseModel = elem.PendingModifiedValues.LicenseModel
			}
			if elem.PendingModifiedValues.MasterUserPassword != nil {
				f42.MasterUserPassword = elem.PendingModifiedValues.MasterUserPassword
			}
			if elem.PendingModifiedValues.MultiAZ != nil {
				f42.MultiAZ = elem.PendingModifiedValues.MultiAZ
			}
			if elem.PendingModifiedValues.PendingCloudwatchLogsExports != nil {
				f42f12 := &svcapitypes.PendingCloudwatchLogsExports{}
				if elem.PendingModifiedValues.PendingCloudwatchLogsExports.LogTypesToDisable != nil {
					f42f12f0 := []*string{}
					for _, f42f12f0iter := range elem.PendingModifiedValues.PendingCloudwatchLogsExports.LogTypesToDisable {
						var f42f12f0elem string
						f42f12f0elem = *f42f12f0iter
						f42f12f0 = append(f42f12f0, &f42f12f0elem)
					}
					f42f12.LogTypesToDisable = f42f12f0
				}
				if elem.PendingModifiedValues.PendingCloudwatchLogsExports.LogTypesToEnable != nil {
					f42f12f1 := []*string{}
					for _, f42f12f1iter := range elem.PendingModifiedValues.PendingCloudwatchLogsExports.LogTypesToEnable {
						var f42f12f1elem string
						f42f12f1elem = *f42f12f1iter
						f42f12f1 = append(f42f12f1, &f42f12f1elem)
					}
					f42f12.LogTypesToEnable = f42f12f1
				}
				f42.PendingCloudwatchLogsExports = f42f12
			}
			if elem.PendingModifiedValues.Port != nil {
				f42.Port = elem.PendingModifiedValues.Port
			}
			if elem.PendingModifiedValues.ProcessorFeatures != nil {
				f42f14 := []*svcapitypes.ProcessorFeature{}
				for _, f42f14iter := range elem.PendingModifiedValues.ProcessorFeatures {
					f42f14elem := &svcapitypes.ProcessorFeature{}
					if f42f14iter.Name != nil {
						f42f14elem.Name = f42f14iter.Name
					}
					if f42f14iter.Value != nil {
						f42f14elem.Value = f42f14iter.Value
					}
					f42f14 = append(f42f14, f42f14elem)
				}
				f42.ProcessorFeatures = f42f14
			}
			if elem.PendingModifiedValues.StorageType != nil {
				f42.StorageType = elem.PendingModifiedValues.StorageType
			}
			cr.Status.AtProvider.PendingModifiedValues = f42
		} else {
			cr.Status.AtProvider.PendingModifiedValues = nil
		}
		if elem.PerformanceInsightsEnabled != nil {
			cr.Status.AtProvider.PerformanceInsightsEnabled = elem.PerformanceInsightsEnabled
		} else {
			cr.Status.AtProvider.PerformanceInsightsEnabled = nil
		}
		if elem.PerformanceInsightsKMSKeyId != nil {
			cr.Spec.ForProvider.PerformanceInsightsKMSKeyID = elem.PerformanceInsightsKMSKeyId
		} else {
			cr.Spec.ForProvider.PerformanceInsightsKMSKeyID = nil
		}
		if elem.PerformanceInsightsRetentionPeriod != nil {
			cr.Spec.ForProvider.PerformanceInsightsRetentionPeriod = elem.PerformanceInsightsRetentionPeriod
		} else {
			cr.Spec.ForProvider.PerformanceInsightsRetentionPeriod = nil
		}
		if elem.PreferredBackupWindow != nil {
			cr.Spec.ForProvider.PreferredBackupWindow = elem.PreferredBackupWindow
		} else {
			cr.Spec.ForProvider.PreferredBackupWindow = nil
		}
		if elem.PreferredMaintenanceWindow != nil {
			cr.Spec.ForProvider.PreferredMaintenanceWindow = elem.PreferredMaintenanceWindow
		} else {
			cr.Spec.ForProvider.PreferredMaintenanceWindow = nil
		}
		if elem.ProcessorFeatures != nil {
			f48 := []*svcapitypes.ProcessorFeature{}
			for _, f48iter := range elem.ProcessorFeatures {
				f48elem := &svcapitypes.ProcessorFeature{}
				if f48iter.Name != nil {
					f48elem.Name = f48iter.Name
				}
				if f48iter.Value != nil {
					f48elem.Value = f48iter.Value
				}
				f48 = append(f48, f48elem)
			}
			cr.Spec.ForProvider.ProcessorFeatures = f48
		} else {
			cr.Spec.ForProvider.ProcessorFeatures = nil
		}
		if elem.PromotionTier != nil {
			cr.Spec.ForProvider.PromotionTier = elem.PromotionTier
		} else {
			cr.Spec.ForProvider.PromotionTier = nil
		}
		if elem.PubliclyAccessible != nil {
			cr.Spec.ForProvider.PubliclyAccessible = elem.PubliclyAccessible
		} else {
			cr.Spec.ForProvider.PubliclyAccessible = nil
		}
		if elem.ReadReplicaDBClusterIdentifiers != nil {
			f51 := []*string{}
			for _, f51iter := range elem.ReadReplicaDBClusterIdentifiers {
				var f51elem string
				f51elem = *f51iter
				f51 = append(f51, &f51elem)
			}
			cr.Status.AtProvider.ReadReplicaDBClusterIdentifiers = f51
		} else {
			cr.Status.AtProvider.ReadReplicaDBClusterIdentifiers = nil
		}
		if elem.ReadReplicaDBInstanceIdentifiers != nil {
			f52 := []*string{}
			for _, f52iter := range elem.ReadReplicaDBInstanceIdentifiers {
				var f52elem string
				f52elem = *f52iter
				f52 = append(f52, &f52elem)
			}
			cr.Status.AtProvider.ReadReplicaDBInstanceIdentifiers = f52
		} else {
			cr.Status.AtProvider.ReadReplicaDBInstanceIdentifiers = nil
		}
		if elem.ReadReplicaSourceDBInstanceIdentifier != nil {
			cr.Status.AtProvider.ReadReplicaSourceDBInstanceIdentifier = elem.ReadReplicaSourceDBInstanceIdentifier
		} else {
			cr.Status.AtProvider.ReadReplicaSourceDBInstanceIdentifier = nil
		}
		if elem.ReplicaMode != nil {
			cr.Status.AtProvider.ReplicaMode = elem.ReplicaMode
		} else {
			cr.Status.AtProvider.ReplicaMode = nil
		}
		if elem.SecondaryAvailabilityZone != nil {
			cr.Status.AtProvider.SecondaryAvailabilityZone = elem.SecondaryAvailabilityZone
		} else {
			cr.Status.AtProvider.SecondaryAvailabilityZone = nil
		}
		if elem.StatusInfos != nil {
			f56 := []*svcapitypes.DBInstanceStatusInfo{}
			for _, f56iter := range elem.StatusInfos {
				f56elem := &svcapitypes.DBInstanceStatusInfo{}
				if f56iter.Message != nil {
					f56elem.Message = f56iter.Message
				}
				if f56iter.Normal != nil {
					f56elem.Normal = f56iter.Normal
				}
				if f56iter.Status != nil {
					f56elem.Status = f56iter.Status
				}
				if f56iter.StatusType != nil {
					f56elem.StatusType = f56iter.StatusType
				}
				f56 = append(f56, f56elem)
			}
			cr.Status.AtProvider.StatusInfos = f56
		} else {
			cr.Status.AtProvider.StatusInfos = nil
		}
		if elem.StorageEncrypted != nil {
			cr.Spec.ForProvider.StorageEncrypted = elem.StorageEncrypted
		} else {
			cr.Spec.ForProvider.StorageEncrypted = nil
		}
		if elem.StorageType != nil {
			cr.Spec.ForProvider.StorageType = elem.StorageType
		} else {
			cr.Spec.ForProvider.StorageType = nil
		}
		if elem.TagList != nil {
			f59 := []*svcapitypes.Tag{}
			for _, f59iter := range elem.TagList {
				f59elem := &svcapitypes.Tag{}
				if f59iter.Key != nil {
					f59elem.Key = f59iter.Key
				}
				if f59iter.Value != nil {
					f59elem.Value = f59iter.Value
				}
				f59 = append(f59, f59elem)
			}
			cr.Status.AtProvider.TagList = f59
		} else {
			cr.Status.AtProvider.TagList = nil
		}
		if elem.TdeCredentialArn != nil {
			cr.Spec.ForProvider.TDECredentialARN = elem.TdeCredentialArn
		} else {
			cr.Spec.ForProvider.TDECredentialARN = nil
		}
		if elem.Timezone != nil {
			cr.Spec.ForProvider.Timezone = elem.Timezone
		} else {
			cr.Spec.ForProvider.Timezone = nil
		}
		if elem.VpcSecurityGroups != nil {
			f62 := []*svcapitypes.VPCSecurityGroupMembership{}
			for _, f62iter := range elem.VpcSecurityGroups {
				f62elem := &svcapitypes.VPCSecurityGroupMembership{}
				if f62iter.Status != nil {
					f62elem.Status = f62iter.Status
				}
				if f62iter.VpcSecurityGroupId != nil {
					f62elem.VPCSecurityGroupID = f62iter.VpcSecurityGroupId
				}
				f62 = append(f62, f62elem)
			}
			cr.Status.AtProvider.VPCSecurityGroups = f62
		} else {
			cr.Status.AtProvider.VPCSecurityGroups = nil
		}
		found = true
		break
	}
	if !found {
		return cr
	}

	return cr
}

// GenerateCreateDBInstanceInput returns a create input.
func GenerateCreateDBInstanceInput(cr *svcapitypes.DBInstance) *svcsdk.CreateDBInstanceInput {
	res := &svcsdk.CreateDBInstanceInput{}

	if cr.Spec.ForProvider.AllocatedStorage != nil {
		res.SetAllocatedStorage(*cr.Spec.ForProvider.AllocatedStorage)
	}
	if cr.Spec.ForProvider.AutoMinorVersionUpgrade != nil {
		res.SetAutoMinorVersionUpgrade(*cr.Spec.ForProvider.AutoMinorVersionUpgrade)
	}
	if cr.Spec.ForProvider.AvailabilityZone != nil {
		res.SetAvailabilityZone(*cr.Spec.ForProvider.AvailabilityZone)
	}
	if cr.Spec.ForProvider.BackupRetentionPeriod != nil {
		res.SetBackupRetentionPeriod(*cr.Spec.ForProvider.BackupRetentionPeriod)
	}
	if cr.Spec.ForProvider.CharacterSetName != nil {
		res.SetCharacterSetName(*cr.Spec.ForProvider.CharacterSetName)
	}
	if cr.Spec.ForProvider.CopyTagsToSnapshot != nil {
		res.SetCopyTagsToSnapshot(*cr.Spec.ForProvider.CopyTagsToSnapshot)
	}
	if cr.Spec.ForProvider.DBClusterIdentifier != nil {
		res.SetDBClusterIdentifier(*cr.Spec.ForProvider.DBClusterIdentifier)
	}
	if cr.Spec.ForProvider.DBInstanceClass != nil {
		res.SetDBInstanceClass(*cr.Spec.ForProvider.DBInstanceClass)
	}
	if cr.Spec.ForProvider.DBName != nil {
		res.SetDBName(*cr.Spec.ForProvider.DBName)
	}
	if cr.Spec.ForProvider.DBParameterGroupName != nil {
		res.SetDBParameterGroupName(*cr.Spec.ForProvider.DBParameterGroupName)
	}
	if cr.Spec.ForProvider.DBSubnetGroupName != nil {
		res.SetDBSubnetGroupName(*cr.Spec.ForProvider.DBSubnetGroupName)
	}
	if cr.Spec.ForProvider.DeletionProtection != nil {
		res.SetDeletionProtection(*cr.Spec.ForProvider.DeletionProtection)
	}
	if cr.Spec.ForProvider.Domain != nil {
		res.SetDomain(*cr.Spec.ForProvider.Domain)
	}
	if cr.Spec.ForProvider.DomainIAMRoleName != nil {
		res.SetDomainIAMRoleName(*cr.Spec.ForProvider.DomainIAMRoleName)
	}
	if cr.Spec.ForProvider.EnableCloudwatchLogsExports != nil {
		f14 := []*string{}
		for _, f14iter := range cr.Spec.ForProvider.EnableCloudwatchLogsExports {
			var f14elem string
			f14elem = *f14iter
			f14 = append(f14, &f14elem)
		}
		res.SetEnableCloudwatchLogsExports(f14)
	}
	if cr.Spec.ForProvider.EnableCustomerOwnedIP != nil {
		res.SetEnableCustomerOwnedIp(*cr.Spec.ForProvider.EnableCustomerOwnedIP)
	}
	if cr.Spec.ForProvider.EnableIAMDatabaseAuthentication != nil {
		res.SetEnableIAMDatabaseAuthentication(*cr.Spec.ForProvider.EnableIAMDatabaseAuthentication)
	}
	if cr.Spec.ForProvider.EnablePerformanceInsights != nil {
		res.SetEnablePerformanceInsights(*cr.Spec.ForProvider.EnablePerformanceInsights)
	}
	if cr.Spec.ForProvider.Engine != nil {
		res.SetEngine(*cr.Spec.ForProvider.Engine)
	}
	if cr.Spec.ForProvider.EngineVersion != nil {
		res.SetEngineVersion(*cr.Spec.ForProvider.EngineVersion)
	}
	if cr.Spec.ForProvider.IOPS != nil {
		res.SetIops(*cr.Spec.ForProvider.IOPS)
	}
	if cr.Spec.ForProvider.KMSKeyID != nil {
		res.SetKmsKeyId(*cr.Spec.ForProvider.KMSKeyID)
	}
	if cr.Spec.ForProvider.LicenseModel != nil {
		res.SetLicenseModel(*cr.Spec.ForProvider.LicenseModel)
	}
	if cr.Spec.ForProvider.MasterUsername != nil {
		res.SetMasterUsername(*cr.Spec.ForProvider.MasterUsername)
	}
	if cr.Spec.ForProvider.MaxAllocatedStorage != nil {
		res.SetMaxAllocatedStorage(*cr.Spec.ForProvider.MaxAllocatedStorage)
	}
	if cr.Spec.ForProvider.MonitoringInterval != nil {
		res.SetMonitoringInterval(*cr.Spec.ForProvider.MonitoringInterval)
	}
	if cr.Spec.ForProvider.MonitoringRoleARN != nil {
		res.SetMonitoringRoleArn(*cr.Spec.ForProvider.MonitoringRoleARN)
	}
	if cr.Spec.ForProvider.MultiAZ != nil {
		res.SetMultiAZ(*cr.Spec.ForProvider.MultiAZ)
	}
	if cr.Spec.ForProvider.NcharCharacterSetName != nil {
		res.SetNcharCharacterSetName(*cr.Spec.ForProvider.NcharCharacterSetName)
	}
	if cr.Spec.ForProvider.OptionGroupName != nil {
		res.SetOptionGroupName(*cr.Spec.ForProvider.OptionGroupName)
	}
	if cr.Spec.ForProvider.PerformanceInsightsKMSKeyID != nil {
		res.SetPerformanceInsightsKMSKeyId(*cr.Spec.ForProvider.PerformanceInsightsKMSKeyID)
	}
	if cr.Spec.ForProvider.PerformanceInsightsRetentionPeriod != nil {
		res.SetPerformanceInsightsRetentionPeriod(*cr.Spec.ForProvider.PerformanceInsightsRetentionPeriod)
	}
	if cr.Spec.ForProvider.Port != nil {
		res.SetPort(*cr.Spec.ForProvider.Port)
	}
	if cr.Spec.ForProvider.PreferredBackupWindow != nil {
		res.SetPreferredBackupWindow(*cr.Spec.ForProvider.PreferredBackupWindow)
	}
	if cr.Spec.ForProvider.PreferredMaintenanceWindow != nil {
		res.SetPreferredMaintenanceWindow(*cr.Spec.ForProvider.PreferredMaintenanceWindow)
	}
	if cr.Spec.ForProvider.ProcessorFeatures != nil {
		f35 := []*svcsdk.ProcessorFeature{}
		for _, f35iter := range cr.Spec.ForProvider.ProcessorFeatures {
			f35elem := &svcsdk.ProcessorFeature{}
			if f35iter.Name != nil {
				f35elem.SetName(*f35iter.Name)
			}
			if f35iter.Value != nil {
				f35elem.SetValue(*f35iter.Value)
			}
			f35 = append(f35, f35elem)
		}
		res.SetProcessorFeatures(f35)
	}
	if cr.Spec.ForProvider.PromotionTier != nil {
		res.SetPromotionTier(*cr.Spec.ForProvider.PromotionTier)
	}
	if cr.Spec.ForProvider.PubliclyAccessible != nil {
		res.SetPubliclyAccessible(*cr.Spec.ForProvider.PubliclyAccessible)
	}
	if cr.Spec.ForProvider.StorageEncrypted != nil {
		res.SetStorageEncrypted(*cr.Spec.ForProvider.StorageEncrypted)
	}
	if cr.Spec.ForProvider.StorageType != nil {
		res.SetStorageType(*cr.Spec.ForProvider.StorageType)
	}
	if cr.Spec.ForProvider.Tags != nil {
		f40 := []*svcsdk.Tag{}
		for _, f40iter := range cr.Spec.ForProvider.Tags {
			f40elem := &svcsdk.Tag{}
			if f40iter.Key != nil {
				f40elem.SetKey(*f40iter.Key)
			}
			if f40iter.Value != nil {
				f40elem.SetValue(*f40iter.Value)
			}
			f40 = append(f40, f40elem)
		}
		res.SetTags(f40)
	}
	if cr.Spec.ForProvider.TDECredentialARN != nil {
		res.SetTdeCredentialArn(*cr.Spec.ForProvider.TDECredentialARN)
	}
	if cr.Spec.ForProvider.TDECredentialPassword != nil {
		res.SetTdeCredentialPassword(*cr.Spec.ForProvider.TDECredentialPassword)
	}
	if cr.Spec.ForProvider.Timezone != nil {
		res.SetTimezone(*cr.Spec.ForProvider.Timezone)
	}

	return res
}

// GenerateModifyDBInstanceInput returns an update input.
func GenerateModifyDBInstanceInput(cr *svcapitypes.DBInstance) *svcsdk.ModifyDBInstanceInput {
	res := &svcsdk.ModifyDBInstanceInput{}

	if cr.Spec.ForProvider.AllocatedStorage != nil {
		res.SetAllocatedStorage(*cr.Spec.ForProvider.AllocatedStorage)
	}
	if cr.Spec.ForProvider.AutoMinorVersionUpgrade != nil {
		res.SetAutoMinorVersionUpgrade(*cr.Spec.ForProvider.AutoMinorVersionUpgrade)
	}
	if cr.Spec.ForProvider.BackupRetentionPeriod != nil {
		res.SetBackupRetentionPeriod(*cr.Spec.ForProvider.BackupRetentionPeriod)
	}
	if cr.Status.AtProvider.CACertificateIdentifier != nil {
		res.SetCACertificateIdentifier(*cr.Status.AtProvider.CACertificateIdentifier)
	}
	if cr.Spec.ForProvider.CopyTagsToSnapshot != nil {
		res.SetCopyTagsToSnapshot(*cr.Spec.ForProvider.CopyTagsToSnapshot)
	}
	if cr.Spec.ForProvider.DBInstanceClass != nil {
		res.SetDBInstanceClass(*cr.Spec.ForProvider.DBInstanceClass)
	}
	if cr.Spec.ForProvider.DBParameterGroupName != nil {
		res.SetDBParameterGroupName(*cr.Spec.ForProvider.DBParameterGroupName)
	}
	if cr.Spec.ForProvider.DBSubnetGroupName != nil {
		res.SetDBSubnetGroupName(*cr.Spec.ForProvider.DBSubnetGroupName)
	}
	if cr.Spec.ForProvider.DeletionProtection != nil {
		res.SetDeletionProtection(*cr.Spec.ForProvider.DeletionProtection)
	}
	if cr.Spec.ForProvider.Domain != nil {
		res.SetDomain(*cr.Spec.ForProvider.Domain)
	}
	if cr.Spec.ForProvider.DomainIAMRoleName != nil {
		res.SetDomainIAMRoleName(*cr.Spec.ForProvider.DomainIAMRoleName)
	}
	if cr.Spec.ForProvider.EnableCustomerOwnedIP != nil {
		res.SetEnableCustomerOwnedIp(*cr.Spec.ForProvider.EnableCustomerOwnedIP)
	}
	if cr.Spec.ForProvider.EnableIAMDatabaseAuthentication != nil {
		res.SetEnableIAMDatabaseAuthentication(*cr.Spec.ForProvider.EnableIAMDatabaseAuthentication)
	}
	if cr.Spec.ForProvider.EnablePerformanceInsights != nil {
		res.SetEnablePerformanceInsights(*cr.Spec.ForProvider.EnablePerformanceInsights)
	}
	if cr.Spec.ForProvider.EngineVersion != nil {
		res.SetEngineVersion(*cr.Spec.ForProvider.EngineVersion)
	}
	if cr.Spec.ForProvider.IOPS != nil {
		res.SetIops(*cr.Spec.ForProvider.IOPS)
	}
	if cr.Spec.ForProvider.LicenseModel != nil {
		res.SetLicenseModel(*cr.Spec.ForProvider.LicenseModel)
	}
	if cr.Spec.ForProvider.MaxAllocatedStorage != nil {
		res.SetMaxAllocatedStorage(*cr.Spec.ForProvider.MaxAllocatedStorage)
	}
	if cr.Spec.ForProvider.MonitoringInterval != nil {
		res.SetMonitoringInterval(*cr.Spec.ForProvider.MonitoringInterval)
	}
	if cr.Spec.ForProvider.MonitoringRoleARN != nil {
		res.SetMonitoringRoleArn(*cr.Spec.ForProvider.MonitoringRoleARN)
	}
	if cr.Spec.ForProvider.MultiAZ != nil {
		res.SetMultiAZ(*cr.Spec.ForProvider.MultiAZ)
	}
	if cr.Spec.ForProvider.OptionGroupName != nil {
		res.SetOptionGroupName(*cr.Spec.ForProvider.OptionGroupName)
	}
	if cr.Spec.ForProvider.PerformanceInsightsKMSKeyID != nil {
		res.SetPerformanceInsightsKMSKeyId(*cr.Spec.ForProvider.PerformanceInsightsKMSKeyID)
	}
	if cr.Spec.ForProvider.PerformanceInsightsRetentionPeriod != nil {
		res.SetPerformanceInsightsRetentionPeriod(*cr.Spec.ForProvider.PerformanceInsightsRetentionPeriod)
	}
	if cr.Spec.ForProvider.PreferredBackupWindow != nil {
		res.SetPreferredBackupWindow(*cr.Spec.ForProvider.PreferredBackupWindow)
	}
	if cr.Spec.ForProvider.PreferredMaintenanceWindow != nil {
		res.SetPreferredMaintenanceWindow(*cr.Spec.ForProvider.PreferredMaintenanceWindow)
	}
	if cr.Spec.ForProvider.ProcessorFeatures != nil {
		f32 := []*svcsdk.ProcessorFeature{}
		for _, f32iter := range cr.Spec.ForProvider.ProcessorFeatures {
			f32elem := &svcsdk.ProcessorFeature{}
			if f32iter.Name != nil {
				f32elem.SetName(*f32iter.Name)
			}
			if f32iter.Value != nil {
				f32elem.SetValue(*f32iter.Value)
			}
			f32 = append(f32, f32elem)
		}
		res.SetProcessorFeatures(f32)
	}
	if cr.Spec.ForProvider.PromotionTier != nil {
		res.SetPromotionTier(*cr.Spec.ForProvider.PromotionTier)
	}
	if cr.Spec.ForProvider.PubliclyAccessible != nil {
		res.SetPubliclyAccessible(*cr.Spec.ForProvider.PubliclyAccessible)
	}
	if cr.Status.AtProvider.ReplicaMode != nil {
		res.SetReplicaMode(*cr.Status.AtProvider.ReplicaMode)
	}
	if cr.Spec.ForProvider.StorageType != nil {
		res.SetStorageType(*cr.Spec.ForProvider.StorageType)
	}
	if cr.Spec.ForProvider.TDECredentialARN != nil {
		res.SetTdeCredentialArn(*cr.Spec.ForProvider.TDECredentialARN)
	}
	if cr.Spec.ForProvider.TDECredentialPassword != nil {
		res.SetTdeCredentialPassword(*cr.Spec.ForProvider.TDECredentialPassword)
	}

	return res
}

// GenerateDeleteDBInstanceInput returns a deletion input.
func GenerateDeleteDBInstanceInput(cr *svcapitypes.DBInstance) *svcsdk.DeleteDBInstanceInput {
	res := &svcsdk.DeleteDBInstanceInput{}

	return res
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "DBInstanceNotFound"
}
