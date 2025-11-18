# Migration to fix ContactPerson fields - drops fullname, ensures first_name and last_name

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("obeeomaapp", "0011_alter_assessmentquestion_options_and_more"),
    ]

    operations = [
        migrations.RunSQL(
            sql="ALTER TABLE obeeomaapp_contactperson DROP COLUMN IF EXISTS fullname;",
            reverse_sql="ALTER TABLE obeeomaapp_contactperson ADD COLUMN fullname VARCHAR(255) NULL;",
        ),
    ]
