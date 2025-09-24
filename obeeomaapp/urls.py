
from django.urls import path
from .views import (AdminDashboardView, MakeRequestView,ApproveRequestView, MakeOrderView,ApproveOrderView,ConfirmGoodsView,AddInvoiceView, ApproveInvoiceView,PayInvoiceView,

 # Optional welcome page
)
from .views import HomeView  # Make sure this import is included

urlpatterns = [
    path('admin-dashboard/', AdminDashboardView.as_view()),
    
    path('', HomeView.as_view()),  # This handles the root URL

    # 🧾 Procurement flow
    path('make-request/', MakeRequestView.as_view(), name='make-request'),

    path('approve-request/<int:request_id>/', ApproveRequestView.as_view()),
    path('make-order/<int:request_id>/', MakeOrderView.as_view()),
    path('approve-order/<int:order_id>/', ApproveOrderView.as_view()),
    path('confirm-goods/<int:order_id>/', ConfirmGoodsView.as_view()),

    # 💳 Invoice and payment flow
    path('add-invoice/<int:order_id>/', AddInvoiceView.as_view()),
    path('approve-invoice/<int:invoice_id>/', ApproveInvoiceView.as_view()),
    path('pay-invoice/<int:invoice_id>/', PayInvoiceView.as_view()),
]
