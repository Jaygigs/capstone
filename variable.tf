variable "ec2_profile" {
   default = "default"
  
}
variable "ec2_region" {
    default = "us-east-1"
  
}
variable "ec2_ami" {
    default = "ami-0aa2b7722dc1b5612"
  
}
variable "ec2_instance_type" {
    default = "t2.micro" 
}
variable "ec2_count" {
    type = number
    default = "3"

}
variable "ec2_sg" {
    default = "sg-01823b269f0186947"
  
}
variable "ec2_subnet_id" {
    default = ["subnet-02c3cd20cb0e78266","subnet-0dcc497ca8ce32b9a"]
  
}
variable "ec2_tags" {
    default = "wals"
  
}