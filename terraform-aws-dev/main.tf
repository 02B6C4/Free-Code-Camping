resource "aws_vpc" "drgn_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "drgn_vpc"
  }
}

resource "aws_vpc_dhcp_options" "drgn_dns" {
  domain_name_servers = ["${var.dns_1}", "${var.dns_2}"]

  tags = {
    Name = "drgn_dns"
  }
}

resource "aws_vpc_dhcp_options_association" "drgn_dns_opts" {
  vpc_id          = aws_vpc.drgn_vpc.id
  dhcp_options_id = aws_vpc_dhcp_options.drgn_dns.id
}

resource "aws_subnet" "drgn_public_subnet" {
  vpc_id                  = aws_vpc.drgn_vpc.id
  cidr_block              = var.subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = var.aws_az

  tags = {
    Name = "drgn_public_subnet"
  }
}

resource "aws_internet_gateway" "drgn_internet_gateway" {
  vpc_id = aws_vpc.drgn_vpc.id

  tags = {
    Name = "drgn_internet_gateway"
  }
}

resource "aws_route_table" "drgn_public_rt" {
  vpc_id = aws_vpc.drgn_vpc.id

  tags = {
    Name = "drgn_public_rt"
  }
}

resource "aws_route" "drgn_default_route" {
  route_table_id         = aws_route_table.drgn_public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.drgn_internet_gateway.id
}

resource "aws_route_table_association" "drgn_public_assc" {
  subnet_id      = aws_subnet.drgn_public_subnet.id
  route_table_id = aws_route_table.drgn_public_rt.id
}

resource "aws_main_route_table_association" "drgn_main_route" {
  vpc_id         = aws_vpc.drgn_vpc.id
  route_table_id = aws_route_table.drgn_public_rt.id
}

resource "aws_security_group" "drgn_sec_group" {
  name        = "drgn_sec_group"
  description = "drgn security group"
  vpc_id      = aws_vpc.drgn_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["${var.my_ip}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_key_pair" "drgn_auth" {
  key_name   = "drgn_key"
  public_key = file("${var.drg_pub_key}")
}

resource "aws_instance" "drgn_node" {
  instance_type          = var.aws_ami_type
  ami                    = data.aws_ami.drgn_ami.id
  key_name               = aws_key_pair.drgn_auth.id
  vpc_security_group_ids = [aws_security_group.drgn_sec_group.id]
  subnet_id              = aws_subnet.drgn_public_subnet.id
  user_data              = file("userdata.tpl")

  root_block_device {
    volume_size = 30
  }

  tags = {
    Name = "drgn_node"
  }

  provisioner "local-exec" {
    command = templatefile("${var.host_os}-ssh-config.tpl", {
      hostname     = self.public_ip,
      user         = "${var.host_user}",
      identityfile = "${var.drg_prv_key}"
    })
    interpreter = var.host_os == "windows" ? ["Powershell", "-Command"] : ["bash", "-c"]
  }
}
