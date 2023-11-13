locals {
  tags = {
    "orgname" = var.orgname
    "Role"    = var.Role
    "owner"   = var.owner
    "tier"    = var.environmentTier
  }
}