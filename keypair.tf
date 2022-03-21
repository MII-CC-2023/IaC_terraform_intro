resource "aws_key_pair" "sshkeyt" {
  key_name   = "sshkeyt"
  public_key = file("~/.ssh/id_rsa.pub")
}