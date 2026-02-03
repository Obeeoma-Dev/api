#!/bin/bash
# Quick fix: Update urls.py directly on droplet and rebuild

echo "🔧 Updating urls.py on droplet..."

# Backup current urls.py
docker-compose exec backend cp /app/obeeomaapp/urls.py /app/obeeomaapp/urls.py.backup

# Create the updated urls.py content
cat > /tmp/urls_update.py << 'EOFPYTHON'
    # Organization & Employee Management
    path('auth/organizations/<int:org_id>/details/', OrganizationDetailView.as_view(), name='organization-details'),
    path('auth/invitations/', InviteView.as_view({'post': 'create', 'get': 'list'}), name='invitation-list'),
    path('auth/invitations/<int:pk>/', InviteView.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update',
        'delete': 'destroy'
    }), name='invitation-detail'),
    path('auth/hotline/active/', ActiveHotlineView.as_view(), name="active-hotline"),
EOFPYTHON

echo "📝 Updated URL configuration created"
echo ""
echo "⚠️  MANUAL STEP REQUIRED:"
echo "You need to edit the file on the droplet manually or copy from your local machine"
echo ""
echo "Option 1: Edit directly in container"
echo "  docker-compose exec backend nano /app/obeeomaapp/urls.py"
echo ""
echo "Option 2: Copy from local (run from your local machine):"
echo "  scp obeeomaapp/urls.py root@YOUR_DROPLET_IP:~/obeeoma_project/api/obeeomaapp/"
echo ""
echo "Then rebuild:"
echo "  docker-compose down"
echo "  docker-compose build"
echo "  docker-compose up -d"
