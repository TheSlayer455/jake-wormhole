terraform {
  required_version = "= 1.17.0"
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "= 4.6.0"
    }
  }
  backend "local" { path = "/state/terraform.tfstate" }
}
provider "docker" { host = "unix:///var/run/docker.sock" }
variable "run_id" { type = string }
variable "source_revision" { type = string }
variable "image" { type = string }
variable "public_input" { type = string }
variable "target_limits" { type = any }
variable "target_ids" { type = list(string) }
variable "target_capabilities" { type = list(string) }
locals {
  prefix = "wormhole-${var.run_id}"
  common = {
    "io.jake-wormhole.run_id" = var.run_id
    "io.jake-wormhole.source_revision" = var.source_revision
  }
}
resource "docker_network" "run" {
  name       = "${local.prefix}-network"
  driver     = "bridge"
  internal   = true
  attachable = false
  ingress    = false
  ipv6       = false
  dynamic "labels" {
    for_each = merge(local.common, { "io.jake-wormhole.role" = "network" })
    content {
      label = labels.key
      value = labels.value
    }
  }
}
resource "docker_container" "target" {
  for_each          = toset(var.target_ids)
  name              = "${local.prefix}-${each.key}"
  image             = var.image
  start             = false
  must_run          = false
  privileged        = false
  read_only         = true
  user              = "0:0"
  restart           = "no"
  rm                = false
  publish_all_ports = false
  network_mode      = "bridge"
  ipc_mode          = "private"
  cgroupns_mode     = "private"
  entrypoint        = ["/usr/bin/python3", "/opt/wormhole/runtime.py"]
  command           = ["target"]
  memory            = var.target_limits.memory
  memory_swap       = var.target_limits.memory_swap
  cpus              = var.target_limits.cpus
  log_driver        = var.target_limits.log_driver
  log_opts          = var.target_limits.log_opts
  destroy_grace_seconds = 2
  security_opts     = ["no-new-privileges:true"]
  env = ["WORMHOLE_RUN_ID=${var.run_id}", "WORMHOLE_RUNTIME_TTL_SECONDS=300"]
  capabilities {
    drop = ["ALL"]
    add  = var.target_capabilities
  }
  tmpfs = {
    "/run" = "rw,nosuid,nodev,noexec,size=16m,mode=0755,uid=0,gid=0"
    "/tmp" = "rw,nosuid,nodev,noexec,size=16m,mode=1777"
  }
  volumes {
    host_path      = var.public_input
    container_path = "/run/input"
    read_only      = true
  }
  networks_advanced { name = docker_network.run.name }
  dynamic "labels" {
    for_each = merge(local.common, { "io.jake-wormhole.role" = "target", "io.jake-wormhole.target_id" = each.key })
    content {
      label = labels.key
      value = labels.value
    }
  }
}
output "run" {
  value = {
    network_id   = docker_network.run.id
    network_name = docker_network.run.name
    targets = { for target_id, target in docker_container.target : target_id => {
      resource_id = target.id
      image = target.image
      network_data = target.network_data
    } }
  }
}
