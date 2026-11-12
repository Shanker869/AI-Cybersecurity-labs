scoutsuite_results =
{
 "provider_code": "aws",
 "services": {
  "ec2": {
   "findings": {
    "ec2-security-group-opens-SSH-port-to-all": {
     "description": "Security group allows SSH (22) from 0.0.0.0/0",
     "level": "danger",
     "flagged_items": 2,
     "items": [
      "ec2.regions.us-east-1.vpcs.vpc-1.security_groups.sg-0web",
      "ec2.regions.us-east-1.vpcs.vpc-1.security_groups.sg-0bastion"
     ]
    },
    "ec2-security-group-opens-RDP-port-to-all": {
     "description": "Security group allows RDP (3389) from 0.0.0.0/0",
     "level": "danger",
     "flagged_items": 0,
     "items": []
    },
    "ec2-ebs-snapshot-public": {
     "description": "EBS snapshot is publicly shared (public_snapshot)",
     "level": "danger",
     "flagged_items": 1,
     "items": [
      "ec2.regions.us-east-1.snapshots.snap-0backup2025"
     ]
    }
   }
  },
  "elb": {
   "findings": {
    "elb-listener-allowing-cleartext": {
     "description": "Load balancer listener allows cleartext HTTP instead of TLS",
     "level": "warning",
     "flagged_items": 1,
     "items": [
      "elb.regions.us-east-1.vpcs.vpc-1.elbs.public-web-lb"
     ]
    }
   }
  }
 }
}