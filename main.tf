# AWS account details
provider "aws" {
        access_key = "${var.access_key}"
        secret_key = "${var.secret_key}"
        region = "${var.region}"
}
data "aws_availability_zones" "all" {}

# VPC
resource "aws_vpc" "moonshot" {
	   cidr_block = "10.10.0.0/16"
	   instance_tenancy = "default"
	   enable_dns_support = "true"
	   enable_dns_hostnames = "true"
	   enable_classiclink = "false"
	   tags{
			Name = "moonshot"
		   }
        }

#SubNet Creation 

resource "aws_subnet" "moonshot_public_1" {
                vpc_id = "${aws_vpc.moonshot.id}"
                cidr_block = "10.10.1.0/24"
                availability_zone = "ap-south-1a"
				tags{
					Name = "moonshot_public_1"
					}
        }
		
resource "aws_subnet" "moonshot_public_2" {
                vpc_id = "${aws_vpc.moonshot.id}"
                cidr_block = "10.10.2.0/24"
                availability_zone = "ap-south-1b"
				tags{
					Name = "moonshot_public_2"
					}
        }

# Internet Gateway 

resource "aws_internet_gateway" "moonshot_gateway" {
                vpc_id = "${aws_vpc.moonshot.id}"
				tags{
					Name = "moonshot_gateway"
					}				
				}	
#Route Table

resource "aws_route_table" "moonshot_public" {
                vpc_id = "${aws_vpc.moonshot.id}"

                route {
                        cidr_block = "0.0.0.0/0"
                        gateway_id = "${aws_internet_gateway.moonshot_gateway.id}"
                }
				tags{
					Name = "moonshot_public_1"
					}	
        }
		
#Route Association public
		
resource "aws_route_table_association" "moonshot_public_1_a" {
                subnet_id = "${aws_subnet.moonshot_public_1.id}"
                route_table_id = "${aws_route_table.moonshot_public.id}"
        }

resource "aws_route_table_association" "moonshot_public_2_b" {
                subnet_id = "${aws_subnet.moonshot_public_2.id}"
                route_table_id = "${aws_route_table.moonshot_public.id}"
        }
	
#Security Group 

resource "aws_security_group" "sg-test" {
  vpc_id = "${aws_vpc.moonshot.id}"

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
          }
    ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
          }
  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
          }
  ingress {
    from_port = 8080
    to_port = 8080
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
        tags{
                Name = "sg-test"
                }

}



#Autoscaling 
	
resource "aws_launch_configuration" "launchconfig" {
	name = "launchconfig"
	image_id = "${lookup(var.ami,var.region)}"
	instance_type = "t2.micro"
	key_name = "moonshot"
	security_groups = ["${aws_security_group.sg-test.id}"]
  associate_public_ip_address = true
  ebs_block_device{
   			 device_name = "/dev/sdf"
	 volume_size = 10
	 volume_type = "gp2"
  }
}

resource "aws_autoscaling_group" "autoscaling" {
	name = "autoscaling"
	vpc_zone_identifier = ["${aws_subnet.moonshot_public_1.id}", "${aws_subnet.moonshot_public_2.id}"]
	launch_configuration = "${aws_launch_configuration.launchconfig.name}"
	min_size = "${var.count}"
	max_size = 5
	health_check_grace_period = 300
	health_check_type = "EC2"
	force_delete = true
	tag {
	key = "Name"
	value = "${format("Server-%03d", count.index + 1)}"
	propagate_at_launch = true
}
}
# Scale up alarm
resource "aws_autoscaling_policy" "cpu-policy" {
	name = "cpu-policy"
	autoscaling_group_name = "${aws_autoscaling_group.autoscaling.name}"
	adjustment_type = "ChangeInCapacity"
	scaling_adjustment = "1"
	cooldown = "300"
	policy_type = "SimpleScaling"
}
resource "aws_cloudwatch_metric_alarm" "cpu-alarm" {
	alarm_name = "cpu-alarm"
	alarm_description = "cpu-alarm"
	comparison_operator = "GreaterThanOrEqualToThreshold"
	evaluation_periods = "2"
	metric_name = "CPUUtilization"
	namespace = "AWS/EC2"
	period = "120"
	statistic = "Average"
	threshold = "30"
	dimensions = {
		"AutoScalingGroupName" = "${aws_autoscaling_group.autoscaling.name}"
	 	     }
	actions_enabled = true
	alarm_actions = ["${aws_autoscaling_policy.cpu-policy.arn}","${aws_sns_topic.user_updates.arn}"]
}

# Scale down alarm
resource "aws_autoscaling_policy" "cpu-policy-scaledown" {
	name = "cpu-policy-scaledown"
	autoscaling_group_name = "${aws_autoscaling_group.autoscaling.name}"
	adjustment_type = "ChangeInCapacity"
	scaling_adjustment = "-1"
	cooldown = "300"
	policy_type = "SimpleScaling"
}
resource "aws_cloudwatch_metric_alarm" "cpu-alarm-scaledown" {
	alarm_name = "cpu-alarm-scaledown"
	alarm_description = "cpu-alarm-scaledown"
	comparison_operator = "LessThanOrEqualToThreshold"
	evaluation_periods = "2"
	metric_name = "CPUUtilization"
	namespace = "AWS/EC2"
	period = "120"
	statistic = "Average"
	threshold = "5"
	dimensions = {
		"AutoScalingGroupName" = "${aws_autoscaling_group.autoscaling.name}"
}
	actions_enabled = true
	alarm_actions = ["${aws_autoscaling_policy.cpu-policy-scaledown.arn}","${aws_sns_topic.user_updates.arn}"]
}


## Security Group for ELB
resource "aws_security_group" "moonshot-elb-sg" {
  name = "moonshot-elb-sg"
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
### Creating ELB
resource "aws_elb" "moonshot-elb" {
  name = "moonshot-elb"
  security_groups = ["${aws_security_group.moonshot-elb-sg.id}"]
  availability_zones = ["${data.aws_availability_zones.all.names}"]
  health_check {
    healthy_threshold = 2
    unhealthy_threshold = 2
    timeout = 3
    interval = 30
    target = "HTTP:8080/"
  }
  listener {
    lb_port = 80
    lb_protocol = "http"
    instance_port = "8080"
    instance_protocol = "http"
  }
}


#S3 Bucket Creation 

resource "aws_s3_bucket" "moonshot" {
  bucket = "moonshot-bucket"
  acl    = "public-read"

  tags = {
    Name        = "My bucket"
    Environment = "Prod"
  }
lifecycle_rule {
    id      = "log"
    enabled = true

    prefix = "log/"

    tags = {
      "rule"      = "log"
      "autoclean" = "true"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA" # or "ONEZONE_IA"
    }

    transition {
      days          = 60
      storage_class = "GLACIER"
    }

    expiration {
      days = 90
    }
  }
#Version Enabled for S3

  versioning {
    enabled = true
  }

	lifecycle_rule {
	    prefix  = "config/"
	    enabled = true

	    noncurrent_version_transition {
	    days          = 30
	    storage_class = "STANDARD_IA"
	    }

	    noncurrent_version_transition {
	    days          = 60
	    storage_class = "GLACIER"
   	    }

	    noncurrent_version_expiration {
	    days = 90
	    }
}
}

#cloudwatch

# SNS topic creation
resource "aws_sns_topic" "user_updates" {
  name = "user-updates-topic"
  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF
   provisioner "local-exec" {
       command = "aws sns subscribe --topic-arn ${self.arn} --protocol email --notification-endpoint ${var.alarms_email}"
    }
}

# policy data for sns
data "aws_iam_policy_document" "sns_topic_policy" {
  statement {
    effect  = "Allow"
    actions = ["SNS:Publish"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = ["${aws_sns_topic.user_updates.arn}"]
  }
}

# assigning policy to publish the events to SQS
resource "aws_sns_topic_policy" "default" {
  arn    = "${aws_sns_topic.user_updates.arn}"
  policy = "${data.aws_iam_policy_document.sns_topic_policy.json}"
}

#SQS queue creation
resource "aws_sqs_queue" "user_updates_queue" {
  name = "user-updates-queue"
}

#subscribe SNS to SQS
resource "aws_sns_topic_subscription" "user_updates_sqs_target" {
  topic_arn = "${aws_sns_topic.user_updates.arn}"
  protocol  = "sqs"
  endpoint  = "${aws_sqs_queue.user_updates_queue.arn}"
}

# add policy to SQS
resource "aws_sqs_queue_policy" "test" {
  queue_url = "${aws_sqs_queue.user_updates_queue.id}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "sqspolicy",
  "Statement": [
    {
      "Sid": "First",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.user_updates_queue.arn}",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "${aws_sns_topic.user_updates.arn}"
        }
      }
    }
  ]
}
POLICY
}

#cloudwatch event rule creation
resource "aws_cloudwatch_event_rule" "ec2_stchng" {
  name        = "capture-ec2_state_changes"
  description = "Capture each change state for EC2 instances"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.ec2"
  ],
  "detail-type": [
    "EC2 Instance State-change Notification"
  ]
}
PATTERN
}

# assign event to SNS topic
resource "aws_cloudwatch_event_target" "sns" {
  rule      = "${aws_cloudwatch_event_rule.ec2_stchng.name}"
  target_id = "SendToSNS"
  arn       = "${aws_sns_topic.user_updates.arn}"
}

resource "aws_cloudwatch_metric_alarm" "health" {
  alarm_name                = "health-alarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "StatusCheckFailed"
  namespace                 = "AWS/EC2"
  period                    = "120"
  statistic                 = "Average"
  threshold                 = "1"
  alarm_description         = "This metric monitors ec2 health status"
  alarm_actions             = [ "${aws_sns_topic.user_updates.arn}" ]

  dimensions {
    InstanceId = "${aws_autoscaling_group.autoscaling.name}"
  }
}
