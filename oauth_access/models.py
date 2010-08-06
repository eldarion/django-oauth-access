import datetime

from django.db import models

from django.contrib.auth.models import User


class UserAssociation(models.Model):
    
    user = models.ForeignKey(User)
    service = models.CharField(max_length=75, db_index=True)
    identifier = models.CharField(max_length=255, db_index=True)
    token = models.CharField(max_length=200)
    expires = models.DateTimeField(null=True)
    
    class Meta:
        unique_together = [("user", "service")]
    
    def expired(self):
        return datetime.datetime.now() < self.expires
