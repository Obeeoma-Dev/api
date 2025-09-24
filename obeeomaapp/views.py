from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.utils.timezone import now
import psutil

from rest_framework.views import APIView
from rest_framework.response import Response

class HomeView(APIView):
    def get(self, request):
        return Response({"message": "Welcome to Obeeoma Admin System"})

class AdminDashboardView(APIView):
    def get(self, request):
        today = now().date()

        # User stats
        total_users = User.objects.count()
        active_users_today = User.objects.filter(last_login__date=today).count()
        total_staff = User.objects.filter(is_staff=True).count()

        # Recent users with avatars
        recent_users = User.objects.order_by('-date_joined')[:5]
        recent_user_data = []
        for user in recent_users:
            avatar_url = None
            if hasattr(user, 'userprofile') and user.userprofile.avatar:
                avatar_url = user.userprofile.avatar.url
            recent_user_data.append({
                "username": user.username,
                "email": user.email,
                "date_joined": user.date_joined,
                "avatar": avatar_url
            })

        # Server health
        server_status = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
        }

        return Response({
            "total_users": total_users,
            "active_users_today": active_users_today,
            "total_staff": total_staff,
            "recent_users": recent_user_data,
            "server_status": server_status,
        })

# 🧾 Create a new purchase request
class MakeRequestView(APIView):
    def post(self, request):
        pr = PurchaseRequest.objects.create(
            created_by=request.user,
            description=request.data.get("description")
        )
        return Response({"message": "Request created", "request_id": pr.id})

# ✅ Approve a purchase request
class ApproveRequestView(APIView):
    def post(self, request, request_id):
        pr = PurchaseRequest.objects.get(id=request_id)
        pr.approved = True
        pr.save()
        return Response({"message": "Request approved"})

# 📦 Create a purchase order from an approved request
class MakeOrderView(APIView):
    def post(self, request, request_id):
        pr = PurchaseRequest.objects.get(id=request_id)
        if not pr.approved:
            return Response({"error": "Request not approved"}, status=400)
        po = PurchaseOrder.objects.create(pr=pr, created_by=request.user)
        return Response({"message": "Order created", "order_id": po.id})

# ✅ Approve a purchase order
class ApproveOrderView(APIView):
    def post(self, request, order_id):
        po = PurchaseOrder.objects.get(id=order_id)
        po.approved = True
        po.save()
        return Response({"message": "Order approved"})

# 📥 Confirm that goods were received
class ConfirmGoodsView(APIView):
    def post(self, request, order_id):
        po = PurchaseOrder.objects.get(id=order_id)
        if not po.approved:
            return Response({"error": "Order not approved"}, status=400)
        receipt = GoodsReceipt.objects.create(po=po, received_by=request.user)
        return Response({"message": "Goods confirmed", "receipt_id": receipt.id})

# 🧾 Add an invoice for a purchase order
class AddInvoiceView(APIView):
    def post(self, request, order_id):
        invoice = Invoice.objects.create(
            po_id=order_id,
            amount=request.data.get("amount")
        )
        return Response({"message": "Invoice added", "invoice_id": invoice.id})

# ✅ Approve an invoice
class ApproveInvoiceView(APIView):
    def post(self, request, invoice_id):
        invoice = Invoice.objects.get(id=invoice_id)
        invoice.approved = True
        invoice.save()
        return Response({"message": "Invoice approved"})

# 💳 Process payment for an approved invoice
class PayInvoiceView(APIView):
    def post(self, request, invoice_id):
        invoice = Invoice.objects.get(id=invoice_id)
        if not invoice.approved:
            return Response({"error": "Invoice not approved"}, status=400)
        payment = Payment.objects.create(
            invoice=invoice,
            processed_by=request.user,
            status="Completed"
        )
        return Response({"message": "Payment completed", "payment_id": payment.id})
