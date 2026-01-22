# Generated manually to fix missing achievement table

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('obeeomaapp', '0021_remove_notification_object_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='Achievement',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('description', models.CharField(blank=True, max_length=500, null=True)),
                ('icon', models.CharField(max_length=50)),
                ('category', models.CharField(choices=[('assessment', 'Assessment'), ('moodtracking', 'Mood Tracking'), ('yourprogress', 'Your Progress'), ('educationalresource', 'Educational Resource')], max_length=30)),
                ('target_count', models.PositiveIntegerField(blank=True, help_text='Number of actions required to unlock this achievement. Leave blank for one-time achievements.', null=True)),
                ('is_active', models.BooleanField(blank=True, default=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['category', 'title'],
            },
        ),
        migrations.CreateModel(
            name='UserAchievement',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('achieved', models.BooleanField(default=False)),
                ('achieved_date', models.DateField(blank=True, null=True)),
                ('progress_count', models.PositiveIntegerField(default=0)),
                ('achievement', models.ForeignKey(default=None, on_delete=django.db.models.deletion.CASCADE, related_name='user_achievements', to='obeeomaapp.achievement')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='auth.user')),
            ],
            options={
                'unique_together': {('user', 'achievement')},
            },
        ),
    ]
