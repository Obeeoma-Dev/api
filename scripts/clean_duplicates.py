# scripts/clean_duplicates.py
# Run with: python manage.py shell < scripts/clean_duplicates.py

from django.contrib.auth import get_user_model
from django.db.models import Count
from django.db import transaction
from obeeomaapp.models import EmployeeInvitation, UserVideoInteraction

User = get_user_model()

# Safety flags
# Set dry_run = False only after you have verified the output and made a backup
dry_run = False            # If True: reports actions but does not modify the DB
skip_superusers = True    # Don't touch superusers
skip_staff = False        # Set True to skip staff users too

# Find duplicate emails (non-null and non-empty)
dupes = (
    User.objects
    .filter(email__isnull=False)
    .exclude(email__exact='')
    .values('email')
    .annotate(email_count=Count('email'))
    .filter(email_count__gt=1)
)

if not dupes:
    print("No duplicate emails found.")
else:
    print(f"Found {dupes.count()} email(s) with duplicates. Dry run: {dry_run}")
    for d in dupes:
        email = d['email']
        users = User.objects.filter(email=email).order_by('id')
        keep = users.first()  # choose the oldest by id to keep
        duplicate_qs = users.exclude(id=keep.id)
        duplicate_ids = list(duplicate_qs.values_list('id', flat=True))

        # Optionally skip if keep user is privileged
        if skip_superusers and getattr(keep, 'is_superuser', False):
            print(f"Skipping {email!r} because kept user id={keep.id} is superuser")
            continue
        if skip_staff and getattr(keep, 'is_staff', False):
            print(f"Skipping {email!r} because kept user id={keep.id} is staff")
            continue

        if not duplicate_ids:
            continue

        print(f"\nEmail {email!r}: keep id={keep.id}, duplicates={duplicate_ids}")

        # Show counts of related EmployeeInvitation rows to be reassigned
        inv_count = EmployeeInvitation.objects.filter(invited_by_id__in=duplicate_ids).count()
        print(f"  Invitations that would be reassigned: {inv_count}")

        if dry_run:
            print("  DRY RUN - no changes made. Set dry_run = False to apply.")
            continue

        # Perform changes inside transaction
        try:
            with transaction.atomic():
                # Reassign invitations (safe update)
                EmployeeInvitation.objects.filter(invited_by_id__in=duplicate_ids).update(invited_by_id=keep.id)
                # Delete duplicate user rows
                deleted, _ = User.objects.filter(id__in=duplicate_ids).delete()
            print(f"  DONE - reassigned invitations and deleted {len(duplicate_ids)} users (deleted rows count: {deleted})")
        except Exception as e:
            print(f"  ERROR while processing {email!r}: {e}")




