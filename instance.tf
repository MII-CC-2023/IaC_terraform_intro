resource "aws_instance" "web" {
  ami           = "ami-07ebfd5b3428b6f4d"
  instance_type = "t2.micro"
  key_name = aws_key_pair.sshkeyt.key_name
  security_groups = [ aws_security_group.allow_ssh.name ]

  tags = {
    Name = "HelloWorld"
  }
}