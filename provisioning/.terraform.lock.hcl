# Verified upstream ZIP and contents; offline init must confirm the contents hash.
provider "registry.terraform.io/kreuzwerker/docker" {
  version     = "4.6.0"
  constraints = "4.6.0"
  hashes = [
    "h1:1jD5QVpeLkdxKEWWJpTzNdxtR0WNNFq28Po4yq9w+VM=",
    "zh:866046fa4938ac1ed5cc58b3c4d36e27433dac1aae50256911e6f28184dcf82e",
  ]
}
