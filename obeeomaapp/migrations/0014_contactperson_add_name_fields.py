# Generated migration to add first_name and last_name fields to ContactPerson

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("obeeomaapp", "0013_contactperson_fix"),
    ]

    operations = [
        migrations.AddField(
            model_name="contactperson",
            name="first_name",
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name="contactperson",
            name="last_name",
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
