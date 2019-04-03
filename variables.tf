#Variable Declaration

#variable "access_key" {}
#variable "secret_key" {}
variable "alarms_email" {}
variable "region" {
  default = "ap-south-1"
}
variable "key_name" {
 		default = "moonshot"
}
variable "aws_keypair" {
  default = "moonshot"
}
variable "count" {
  default = "2"
}
variable "ami" {
  default {
    ap-south-1 = "ami-5b673c34"
  }
}
