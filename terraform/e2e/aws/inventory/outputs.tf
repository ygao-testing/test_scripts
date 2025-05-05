output "bastion_a_ip" {
  value = aws_instance.bastion.public_ip
}

output "compute_web1_a_ip" {
  value = aws_instance.web_server1.private_ip
}
output "compute_web2_a_ip" {
  value = aws_instance.web_server2.private_ip
}
output "inspection_vpc_id" {
  value = aws_vpc.fwaas_vpc.id
}

output "inspection_vpc_name" {
  value = aws_vpc.fwaas_vpc.tags.Name
}

output "inspection_subnet_id" {
  value = aws_subnet.endpoint_subnet.id
}
output "s3_bucket_names" {
  value = [
    aws_s3_bucket.s3_bucket.bucket,
    aws_s3_bucket.s3_bucket_bpa_disabled_versioning_enabled.bucket,
    aws_s3_bucket.s3_bucket_deny_http.bucket,
    aws_s3_bucket.s3_bucket_get_public_bpa_disabled.bucket,
    aws_s3_bucket.s3_bucket_global_list_bpa_disabled.bucket
  ]
}
output "lacework_expected_compliance" {
  value = {
    s3 = {
      "lacework-global-50" = {
        compliant     = [aws_s3_bucket.s3_bucket.arn, aws_s3_bucket.s3_bucket_deny_http.arn]
        non_compliant = [aws_s3_bucket.s3_bucket_bpa_disabled_versioning_enabled.arn,aws_s3_bucket.s3_bucket_get_public_bpa_disabled.arn]
      }
      "lacework-global-72" = {
        compliant     = [aws_s3_bucket.s3_bucket.arn,
    aws_s3_bucket.s3_bucket_bpa_disabled_versioning_enabled.arn,
    aws_s3_bucket.s3_bucket_deny_http.arn,
    aws_s3_bucket.s3_bucket_get_public_bpa_disabled.arn,
    aws_s3_bucket.s3_bucket_global_list_bpa_disabled.arn]
        non_compliant = []
      }
      "lacework-global-73" = {
        compliant     = [aws_s3_bucket.s3_bucket_deny_http.arn,]
        non_compliant = [aws_s3_bucket.s3_bucket.arn,
    aws_s3_bucket.s3_bucket_bpa_disabled_versioning_enabled.arn,
    aws_s3_bucket.s3_bucket_get_public_bpa_disabled.arn,
    aws_s3_bucket.s3_bucket_global_list_bpa_disabled.arn]
      }
      "lacework-global-97" = {
        compliant     = [aws_s3_bucket.s3_bucket_bpa_disabled_versioning_enabled.arn]
        non_compliant = [aws_s3_bucket.s3_bucket.arn, aws_s3_bucket.s3_bucket_get_public_bpa_disabled.arn,
        aws_s3_bucket.s3_bucket_deny_http.arn,
        aws_s3_bucket.s3_bucket_get_public_bpa_disabled.arn,
        aws_s3_bucket.s3_bucket_global_list_bpa_disabled.arn]
      }
      "lacework-global-98" = {
        compliant     = [aws_s3_bucket.s3_bucket.arn, aws_s3_bucket.s3_bucket_bpa_disabled_versioning_enabled.arn,
        aws_s3_bucket.s3_bucket_deny_http.arn, aws_s3_bucket.s3_bucket_global_list_bpa_disabled.arn ]
        non_compliant = [aws_s3_bucket.s3_bucket_get_public_bpa_disabled.arn]
      }
      "lacework-global-100" = {
        compliant     = [aws_s3_bucket.s3_bucket.arn, aws_s3_bucket.s3_bucket_bpa_disabled_versioning_enabled.arn,
        aws_s3_bucket.s3_bucket_get_public_bpa_disabled.arn, aws_s3_bucket.s3_bucket.arn,
        aws_s3_bucket.s3_bucket_bpa_disabled_versioning_enabled.arn]
        non_compliant = [aws_s3_bucket.s3_bucket_global_list_bpa_disabled.arn]
      }
       "lacework-global-140" = {
        compliant     = [aws_s3_bucket.s3_bucket.arn,
        aws_s3_bucket.s3_bucket_bpa_disabled_versioning_enabled.arn,
        aws_s3_bucket.s3_bucket_deny_http.arn,]
        non_compliant = [aws_s3_bucket.s3_bucket_global_list_bpa_disabled.arn, aws_s3_bucket.s3_bucket_get_public_bpa_disabled.arn]
      }

  }
  iam-role = {
      "lacework-global-486" = {
        compliant = [
          aws_iam_role.gha_ingestion_role_1.arn,
          aws_iam_role.gha_ingestion_role_2.arn
        ]
        non_compliant = []
      }
    }
    iam-user = {
      "lacework-global-44" = {
        compliant     = [
          aws_iam_user.gha_ingestion_user1.arn,
          aws_iam_user.gha_ingestion_user2.arn,
          aws_iam_user.user_with_2_access_keys_user1.arn,
          aws_iam_user.user_with_2_access_keys_user2.arn
        ]
        non_compliant = []
      }
      "lacework-global-45" = {
        compliant     = [
          aws_iam_user.gha_ingestion_user1.arn,
          aws_iam_user.gha_ingestion_user2.arn,
          aws_iam_user.user_with_2_access_keys_user1.arn,
          aws_iam_user.user_with_2_access_keys_user2.arn
        ]
        non_compliant = []
      }
      "lacework-global-42" = {
        compliant = [
          aws_iam_user.gha_ingestion_user1.arn,
          aws_iam_user.gha_ingestion_user2.arn
        ]
        non_compliant = [
          aws_iam_user.user_with_2_access_keys_user1.arn,
          aws_iam_user.user_with_2_access_keys_user2.arn
        ]
      }
    }
    iam-group = {
      "lacework-global-485" = {
        compliant = [
          aws_iam_group.gha_ingestion_group1.arn,
          aws_iam_group.gha_ingestion_group2.arn
        ]
        non_compliant = []
      }
    }
}
}
