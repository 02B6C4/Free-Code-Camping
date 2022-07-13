variable "host_os" {
  type    = string
  default = "windows"
}

variable "host_user" {
  type    = string
  default = "ubuntu"
}

variable "drg_pub_key" {
  type    = string
  default = "~/.ssh/drgn_key.pub"
}

variable "drg_prv_key" {
  type    = string
  default = "~/.ssh/drgn_key"
}

variable "aws_ami_type" {
  type    = string
  default = "t2.micro"
}

variable "dns_1" {
  type    = string
  default = "9.9.9.9"
}

variable "dns_2" {
  type    = string
  default = "149.112.112.112"
}
