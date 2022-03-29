# Introducción a Terraform

## Instalación
(Actualización: 21 marzo 2022)

Desde la página de downloads de terraform (https://www.terraform.io/downloads.html) descarga la versión adecuada para tu sistema operativo
(descargaremos aquí la versión para Linux 64 bits)

```
$ wget https://releases.hashicorp.com/terraform/1.1.7/terraform_1.1.7_linux_amd64.zip

``` 

Descomprime el fichero usando unzip (si lo necesitas instala el paquete unzip):

```
$ sudo apt install unzip

$ unzip terraform_1.1.7_linux_amd64.zip
```

Mueve el fichero terraform ha una carpeta incluida en el PATH, por ejemplo a /usr/local/bin/:

```
$ sudo mv terraform /usr/local/bin
```

Prueba la instalación con:

```
$ terraform -version
Terraform v1.1.7
```

## Comandos Terraform

Muestra la ayuda sobre los comandos disponibles con:

```
$ terraform -help
Usage: terraform [global options] <subcommand> [args]

The available commands for execution are listed below.
The primary workflow commands are given first, followed by
less common or more advanced commands.

Main commands:
  init          Prepare your working directory for other commands
  validate      Check whether the configuration is valid
  plan          Show changes required by the current configuration
  apply         Create or update infrastructure
  destroy       Destroy previously-created infrastructure

All other commands:
  console       Try Terraform expressions at an interactive command prompt
  fmt           Reformat your configuration in the standard style
  force-unlock  Release a stuck lock on the current workspace
  get           Install or upgrade remote Terraform modules
  graph         Generate a Graphviz graph of the steps in an operation
  import        Associate existing infrastructure with a Terraform resource
  login         Obtain and save credentials for a remote host
  logout        Remove locally-stored credentials for a remote host
  output        Show output values from your root module
  providers     Show the providers required for this configuration
  refresh       Update the state to match remote systems
  show          Show the current state or a saved plan
  state         Advanced state management
  taint         Mark a resource instance as not fully functional
  untaint       Remove the 'tainted' state from a resource instance
  version       Show the current Terraform version
  workspace     Workspace management

Global options (use these before the subcommand, if any):
  -chdir=DIR    Switch to a different working directory before executing the
                given subcommand.
  -help         Show this help output, or the help for a specified subcommand.
  -version      An alias for the "version" subcommand.

```

O la ayuda de un subcomando específico

```
$ terraform -help
Usage: terraform [global options] plan [options]

  Generates a speculative execution plan, showing what actions Terraform
  would take to apply the current configuration. This command will not
  actually perform the planned actions.

  You can optionally save the plan to a file, which you can then pass to
  the "apply" command to perform exactly the actions described in the plan.

Plan Customization Options:
...
```


## Aspectos básicos. Documentación

La infracestructura con Terraform se crea mediante un conjunto de ficheros (.tf),
llamados ficheros de configuración, que incluyen: identificación del proveedor o proveedores,
creación de recursos y definición de variables, outputs, etc.

Puedes obtener información sobre los proveedores en:

https://www.terraform.io/docs/providers/index.html

Dentro de cada proveedor puedes consultar la documentación para crear los recursos disponibles:

Para AWS: https://www.terraform.io/docs/providers/aws/index.html

Para GCP: https://www.terraform.io/docs/providers/google/index.html

En la documentacióm para cada recurso de un proveedor, tenemos los "Data source" con la información
que podemos utilizar de cada recurso y los "Resources" con los parámetros y los atributos para crearlo.
En ambos casos, tenemos varios ejemplos.

Puedes consultar más información sobre otros elementos:

Variables: https://www.terraform.io/docs/configuration/variables.html

Outputs: https://www.terraform.io/docs/configuration/outputs.html

Funciones: https://www.terraform.io/docs/configuration/functions.html

Módulos: https://www.terraform.io/docs/configuration/modules.html


## Ejemplo

En el siguiente ejemplo usaremos AWS:

### Asignando el proveedor

```
# Terraform 0.13 and later
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

# Authentication and Configuration of the AWS Provider

provider "aws" {
  region     = "us-east-1"
  
  # ~/.aws/credentials
  profile = "default"

  # Alternativamente, aunque desaconsejado, se pueden incluir los valores aquí
  # access_key = "ACCESSKEY"
  # secret_key = "SECRETKEY"
  # token      = "SESSIONTOKEN"
}
```


### Crear una SSH key pair 

```
resource "aws_key_pair" "sshkeyt" {
  key_name   = "sshkeyt"
  public_key = file("~/.ssh/id_rsa.pub")
}
```

### Crear una grupo de seguridad

Este grupo de seguridad permite tráfico SSH de entrada y todo el de salida

```
resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"

  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ALLOW_SSH"
  }
}
```
### Crear una instancia 

Esta instancia tendrá la Key pair y el grupo de seguridad creadas anteriormente

```
resource "aws_instance" "web" {
  ami           = "ami-07ebfd5b3428b6f4d"
  instance_type = "t2.micro"
  key_name = aws_key_pair.sshkeyt.key_name
  security_groups = [ aws_security_group.allow_ssh.name ]

  tags = {
    Name = "HelloWorld"
  }
}
```

## Iniciar Terraform

Antes de utilizar terraform es necesario inicializarlo para que se descargue lo necesario
para trabajar con los proveedores y elementos definidos en los ficheros de configuración (.tf)

```
$ terraform init

Initializing the backend...

Initializing provider plugins...
- Finding latest version of hashicorp/aws...
- Installing hashicorp/aws v3.33.0...
- Installed hashicorp/aws v3.33.0 (signed by HashiCorp)

Terraform has created a lock file .terraform.lock.hcl to record the provider
selections it made above. Include this file in your version control repository
so that Terraform can guarantee to make the same selections by default when
you run "terraform init" in the future.

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```


## Planear la infraestructura

```
$ terraform plan

Refreshing Terraform state in-memory prior to plan...
The refreshed state will be used to calculate this plan, but will not be
persisted to local or remote state storage.


------------------------------------------------------------------------

An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_instance.web will be created
  + resource "aws_instance" "web" {
      + ami                          = "ami-07ebfd5b3428b6f4d"
      + arn                          = (known after apply)
      + associate_public_ip_address  = (known after apply)
      + availability_zone            = (known after apply)
      + cpu_core_count               = (known after apply)
      + cpu_threads_per_core         = (known after apply)
      + get_password_data            = false
      + host_id                      = (known after apply)
      + id                           = (known after apply)
      + instance_state               = (known after apply)
      + instance_type                = "t2.micro"
      + ipv6_address_count           = (known after apply)
      + ipv6_addresses               = (known after apply)
      + key_name                     = "sshkeyt"
      + network_interface_id         = (known after apply)
      + password_data                = (known after apply)
      + placement_group              = (known after apply)
      + primary_network_interface_id = (known after apply)
      + private_dns                  = (known after apply)
      + private_ip                   = (known after apply)
      + public_dns                   = (known after apply)
      + public_ip                    = (known after apply)
      + security_groups              = [
          + "allow_ssh",
        ]
      + source_dest_check            = true
      + subnet_id                    = (known after apply)
      + tags                         = {
          + "Name" = "HelloWorld"
        }
      + tenancy                      = (known after apply)
      + volume_tags                  = (known after apply)
      + vpc_security_group_ids       = (known after apply)

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = (known after apply)
          + http_put_response_hop_limit = (known after apply)
          + http_tokens                 = (known after apply)
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # aws_key_pair.sshkeyt will be created
  + resource "aws_key_pair" "sshkeyt" {
      + fingerprint = (known after apply)
      + id          = (known after apply)
      + key_name    = "sshkeyt"
      + key_pair_id = (known after apply)
      + public_key  = "ssh-rsa B3NzaC1yc2EAAAADAQABAAABAQDwNYRwR5CZrOgjhy2RtrJB5Dx6S0XiWxrCRou+yMQ2jcHdBgHqNv/9quUztiyZLwl/tH4fYhfyYVzQO4Pw4tTU2XNiOSHW2yE6Ht6lIH54lM+MbU+MsHQOSAV72lcCXZ0DyJ/Kbt0MUkFZQtooltCkoYn1mOCLYxrx5BmC7E5nW1G3X5RDvpT5gPV2OjxEITxC04X+cXz/A5lL2pb1010XtpeAMHJT4gxFiI1s8VLwrD2vx2DO296yWibeLE9qWQC7YxeRv1VrMF+qirJc3yP74l736DNah8QRvdSv6AUNOesrAgpFO5UP9MQW861db/QwNxsI28VO0hrEoN+WPw1r ec2-user@ip-172-31-82-119"
    }

  # aws_security_group.allow_ssh will be created
  + resource "aws_security_group" "allow_ssh" {
      + arn                    = (known after apply)
      + description            = "Allow SSH inbound traffic"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "SSH from VPC"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
        ]
      + name                   = "allow_ssh"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "ALLOW_SSH"
        }
      + vpc_id                 = (known after apply)
    }

Plan: 3 to add, 0 to change, 0 to destroy.

------------------------------------------------------------------------

Note: You didn't specify an "-out" parameter to save this plan, so Terraform
can't guarantee that exactly these actions will be performed if
"terraform apply" is subsequently run.
```



## Aplica la infraestructura

```
$ terraform apply

An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_instance.web will be created
  + resource "aws_instance" "web" {
      + ami                          = "ami-07ebfd5b3428b6f4d"
      + arn                          = (known after apply)
      + associate_public_ip_address  = (known after apply)
      + availability_zone            = (known after apply)
      + cpu_core_count               = (known after apply)
      + cpu_threads_per_core         = (known after apply)
      + get_password_data            = false
      + host_id                      = (known after apply)
      + id                           = (known after apply)
      + instance_state               = (known after apply)
      + instance_type                = "t2.micro"
      + ipv6_address_count           = (known after apply)
      + ipv6_addresses               = (known after apply)
      + key_name                     = "sshkeyt"
      + network_interface_id         = (known after apply)
      + password_data                = (known after apply)
      + placement_group              = (known after apply)
      + primary_network_interface_id = (known after apply)
      + private_dns                  = (known after apply)
      + private_ip                   = (known after apply)
      + public_dns                   = (known after apply)
      + public_ip                    = (known after apply)
      + security_groups              = [
          + "allow_ssh",
        ]
      + source_dest_check            = true
      + subnet_id                    = (known after apply)
      + tags                         = {
          + "Name" = "HelloWorld"
        }
      + tenancy                      = (known after apply)
      + volume_tags                  = (known after apply)
      + vpc_security_group_ids       = (known after apply)

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = (known after apply)
          + http_put_response_hop_limit = (known after apply)
          + http_tokens                 = (known after apply)
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # aws_key_pair.sshkeyt will be created
  + resource "aws_key_pair" "sshkeyt" {
      + fingerprint = (known after apply)
      + id          = (known after apply)
      + key_name    = "sshkeyt"
      + key_pair_id = (known after apply)
      + public_key  = "ssh-rsa B3NzaC1yc2EAAAADAQABAAABAQDwNYRwR5CZrOgjhy2RtrJB5Dx6S0XiWxrCRou+yMQ2jcHdBgHqNv/9quUztiyZLwl/tH4fYhfyYVzQO4Pw4tTU2XNiOSHW2yE6Ht6lIH54lM+MbU+MsHQOSAV72lcCXZ0DyJ/Kbt0MUkFZQtooltCkoYn1mOCLYxrx5BmC7E5nW1G3X5RDvpT5gPV2OjxEITxC04X+cXz/A5lL2pb1010XtpeAMHJT4gxFiI1s8VLwrD2vx2DO296yWibeLE9qWQC7YxeRv1VrMF+qirJc3yP74l736DNah8QRvdSv6AUNOesrAgpFO5UP9MQW861db/QwNxsI28VO0hrEoN+WPw1r ec2-user@ip-172-31-82-119"
    }

  # aws_security_group.allow_ssh will be created
  + resource "aws_security_group" "allow_ssh" {
      + arn                    = (known after apply)
      + description            = "Allow SSH inbound traffic"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "SSH from VPC"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
        ]
      + name                   = "allow_ssh"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "ALLOW_SSH"
        }
      + vpc_id                 = (known after apply)
    }

Plan: 3 to add, 0 to change, 0 to destroy.

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.
                                               .<< Introduce yes >>
  Enter a value: yes        <-----------------´

aws_key_pair.sshkeyt: Creating...
aws_security_group.allow_ssh: Creating...
aws_key_pair.sshkeyt: Creation complete after 0s [id=sshkeyt]
aws_security_group.allow_ssh: Creation complete after 1s [id=sg-0e8abe1c8e1bacafd]
aws_instance.web: Creating...
aws_instance.web: Still creating... [10s elapsed]
aws_instance.web: Still creating... [20s elapsed]
aws_instance.web: Still creating... [30s elapsed]
aws_instance.web: Still creating... [40s elapsed]
aws_instance.web: Still creating... [50s elapsed]
aws_instance.web: Creation complete after 52s [id=i-0fd9cfb301e1ec897]

Apply complete! Resources: 3 added, 0 changed, 0 destroyed.

```


## Destruye la infraestructura

```
$ terraform destroy

aws_security_group.allow_ssh: Refreshing state... [id=sg-0e8abe1c8e1bacafd]
aws_key_pair.sshkeyt: Refreshing state... [id=sshkeyt]
aws_instance.web: Refreshing state... [id=i-0fd9cfb301e1ec897]

An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  - destroy

Terraform will perform the following actions:

  # aws_instance.web will be destroyed
  - resource "aws_instance" "web" {
      - ami                          = "ami-07ebfd5b3428b6f4d" -> null
      - arn                          = "arn:aws:ec2:us-east-1:139527570839:instance/i-0fd9cfb301e1ec897" -> null
      - associate_public_ip_address  = true -> null
      - availability_zone            = "us-east-1a" -> null
      - cpu_core_count               = 1 -> null
      - cpu_threads_per_core         = 1 -> null
      - disable_api_termination      = false -> null
      - ebs_optimized                = false -> null
      - get_password_data            = false -> null
      - hibernation                  = false -> null
      - id                           = "i-0fd9cfb301e1ec897" -> null
      - instance_state               = "running" -> null
      - instance_type                = "t2.micro" -> null
      - ipv6_address_count           = 0 -> null
      - ipv6_addresses               = [] -> null
      - key_name                     = "sshkeyt" -> null
      - monitoring                   = false -> null
      - primary_network_interface_id = "eni-0699d9722b0bd22a5" -> null
      - private_dns                  = "ip-172-31-35-47.ec2.internal" -> null
      - private_ip                   = "172.31.35.47" -> null
      - public_dns                   = "ec2-54-211-98-247.compute-1.amazonaws.com" -> null
      - public_ip                    = "54.211.98.247" -> null
      - security_groups              = [
          - "allow_ssh",
        ] -> null
      - source_dest_check            = true -> null
      - subnet_id                    = "subnet-112e204d" -> null
      - tags                         = {
          - "Name" = "HelloWorld"
        } -> null
      - tenancy                      = "default" -> null
      - volume_tags                  = {} -> null
      - vpc_security_group_ids       = [
          - "sg-0e8abe1c8e1bacafd",
        ] -> null

      - credit_specification {
          - cpu_credits = "standard" -> null
        }

      - metadata_options {
          - http_endpoint               = "enabled" -> null
          - http_put_response_hop_limit = 1 -> null
          - http_tokens                 = "optional" -> null
        }

      - root_block_device {
          - delete_on_termination = true -> null
          - encrypted             = false -> null
          - iops                  = 100 -> null
          - volume_id             = "vol-09618c5a31eb71050" -> null
          - volume_size           = 8 -> null
          - volume_type           = "gp2" -> null
        }
    }

  # aws_key_pair.sshkeyt will be destroyed
  - resource "aws_key_pair" "sshkeyt" {
      - fingerprint = "cb:90:9d:b8:53:ed:fb:3d:0a:b2:19:c6:9c:0b:8e:aa" -> null
      - id          = "sshkeyt" -> null
      - key_name    = "sshkeyt" -> null
      - key_pair_id = "key-094f138411cabb2c6" -> null
      - public_key  = "ssh-rsa B3NzaC1yc2EAAAADAQABAAABAQDwNYRwR5CZrOgjhy2RtrJB5Dx6S0XiWxrCRou+yMQ2jcHdBgHqNv/9quUztiyZLwl/tH4fYhfyYVzQO4Pw4tTU2XNiOSHW2yE6Ht6lIH54lM+MbU+MsHQOSAV72lcCXZ0DyJ/Kbt0MUkFZQtooltCkoYn1mOCLYxrx5BmC7E5nW1G3X5RDvpT5gPV2OjxEITxC04X+cXz/A5lL2pb1010XtpeAMHJT4gxFiI1s8VLwrD2vx2DO296yWibeLE9qWQC7YxeRv1VrMF+qirJc3yP74l736DNah8QRvdSv6AUNOesrAgpFO5UP9MQW861db/QwNxsI28VO0hrEoN+WPw1r ec2-user@ip-172-31-82-119" -> null
      - tags        = {} -> null
    }

  # aws_security_group.allow_ssh will be destroyed
  - resource "aws_security_group" "allow_ssh" {
      - arn                    = "arn:aws:ec2:us-east-1:139527570839:security-group/sg-0e8abe1c8e1bacafd" -> null
      - description            = "Allow SSH inbound traffic" -> null
      - egress                 = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 0
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "-1"
              - security_groups  = []
              - self             = false
              - to_port          = 0
            },
        ] -> null
      - id                     = "sg-0e8abe1c8e1bacafd" -> null
      - ingress                = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = "SSH from VPC"
              - from_port        = 22
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 22
            },
        ] -> null
      - name                   = "allow_ssh" -> null
      - owner_id               = "139527570839" -> null
      - revoke_rules_on_delete = false -> null
      - tags                   = {
          - "Name" = "ALLOW_SSH"
        } -> null
      - vpc_id                 = "vpc-6dc99717" -> null
    }

Plan: 0 to add, 0 to change, 3 to destroy.

Do you really want to destroy all resources?
  Terraform will destroy all your managed infrastructure, as shown above.
  There is no undo. Only 'yes' will be accepted to confirm.

  Enter a value: yes

aws_instance.web: Destroying... [id=i-0fd9cfb301e1ec897]
aws_instance.web: Still destroying... [id=i-0fd9cfb301e1ec897, 10s elapsed]
aws_instance.web: Still destroying... [id=i-0fd9cfb301e1ec897, 20s elapsed]
aws_instance.web: Destruction complete after 29s
aws_key_pair.sshkeyt: Destroying... [id=sshkeyt]
aws_security_group.allow_ssh: Destroying... [id=sg-0e8abe1c8e1bacafd]
aws_key_pair.sshkeyt: Destruction complete after 1s
aws_security_group.allow_ssh: Destruction complete after 1s

Destroy complete! Resources: 3 destroyed.
```





