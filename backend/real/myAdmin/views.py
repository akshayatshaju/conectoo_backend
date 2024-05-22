from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from user.serializers import UserRegisterSerializer, UserLoginSerializer, GetUserSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAdminUser,IsAuthenticated
from rest_framework import permissions
from rest_framework.authentication import authenticate
# from django.contrib.auth import authenticate
from user.models import Account
from rest_framework_simplejwt.authentication import JWTAuthentication
from posts.models import *
from posts.serializer import *
from django.db.models.functions import ExtractMonth,ExtractYear,ExtractDay,TruncDate,TruncMonth,TruncYear
from django.db.models import F,Q ,Count
from user.serializers import JoiningMonthCountSerializer
from user.serializers import JoiningYearCountSerializer
# Create your views here.
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.permissions import IsAuthenticated


#get all registerd user
class RegisteredUsers(APIView):
 
    def get(self,request):
        users = Account.objects.filter(is_superuser=False)
        serializer = GetUserSerializer(instance=users, many=True)
        print(serializer)
        return Response(serializer.data,status=200)


class UserDetail(APIView):
    def get(self, request, userEmail):
        try:
            # print("Requested details of user:", userEmail)
            detail = Account.objects.get(email=userEmail)
            # print(detail,"userdetaill")
            serializer = GetUserSerializer(instance=detail)
            # print(serializer.data)
            return Response(serializer.data, status=200)
        except ObjectDoesNotExist:
            return Response({"error": "User not found"}, status=404)
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            return Response({"error": "Internal Server Error"}, status=500)







# block user with id
class BlockUser(APIView):
    def patch(self, request, id):
        try:
            user = Account.objects.get(id=id)
            print(user.is_active,"in block fun checking user")
            b = user.is_active
            user.is_active = not b
            print(user.is_active,"after change")
            user.save()
            return Response({"message": "success"}, status=status.HTTP_200_OK)
        except Account.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            return Response({"message": "Internal Server Error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# delete user with id
class DeleteUser(APIView):
   
    def patch(self, request, id):
        try:
            user = Account.objects.get(id=id)
            user.is_deleted = True
            user.save()
            return Response({"message": "success"}, status=status.HTTP_200_OK)
        except Account.DoesNotExist:
            print("user not found")
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)


# block user with id
class BlockUser(APIView):
    def patch(self, request, id):
        try:
            user = Account.objects.get(id=id)
            print(user.is_active,"in block fun checking user")
            b = user.is_active
            user.is_active = not b
            print(user.is_active,"after change")
            user.save()
            return Response({"message": "success"}, status=status.HTTP_200_OK)
        except Account.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            return Response({"message": "Internal Server Error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
#-------------------------graph for month and year-------------------------------------------#

class UserCountByMonth(APIView):
       def get(self, request):
        user_counts = (
            Account.objects.annotate(
                joining_month=ExtractMonth('date_joined'),
                joining_year=ExtractYear('date_joined')
            )
            .values('joining_month', 'joining_year')
            .annotate(user_count=Count('id'))
            .order_by('joining_year', 'joining_month')
        )
        serializer = JoiningMonthCountSerializer(user_counts, many=True)

        return Response(serializer.data)
    
class UserCountByYear(APIView):
    def get(self, request):
        user_counts = (
            Account.objects.annotate(
                joining_year=ExtractYear('date_joined')
            )
            .values('joining_year')
            .annotate(user_count=Count('id'))
            .order_by('joining_year')
        )
        serializer = JoiningYearCountSerializer(user_counts, many=True)
        return Response(serializer.data)
    
#-----------------------------deltepost-------------------------#
    
class DeletePost(APIView):
    def delete(self,request,id):
        try:
            p = Post.objects.get(id=id)
            p.delete()
            return Response({"message": "success"}, status=status.HTTP_200_OK)
        except Post.DoesNotExist:
            print("post not found")
            return Response({"message": "Post not found"}, status=status.HTTP_404_NOT_FOUND)
       
       
       
        

class DeleteComment(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, id):
        try:
            comment = Comment.objects.get(id=id)
            comment.delete()
            return Response({"message": "Comment deleted successfully"}, status=status.HTTP_200_OK)
        except Comment.DoesNotExist:
            print("Comment not found")
            return Response({"message": "Comment not found"}, status=status.HTTP_404_NOT_FOUND)
        
        
class AdminUserPosts(APIView):
    # permission_classes=[IsAdminUser]
    def get(self,request,userEmail):
        print(" requested for details of user")
        detail = Account.objects.get(email=userEmail)
        print(detail)
        p = Post.objects.filter(user=detail)
        serializer = GetPostSerializer(instance=p,many=True,context={'request':request})
        print(serializer.data)
        return Response(serializer.data,status=200)
    
    
class AdminUserPostsDetails(APIView):
    # permission_classes=[IsAdminUser]
    def get(self,request,id):
        p = Post.objects.filter(id=id)
        print(p)
        serializer = GetPostSerializer(instance=p,many=True,context={'request':request})
        print(serializer.data)
        return Response(serializer.data,status=200)
    
    
#------------------blockpost------------------------------------

class BlockPost(APIView):
    def post(self, request, id):
        try:
            post = Post.objects.get(id=id)
            action = request.data.get("action", None)
            if action == "block":
                if not post.blocked:
                    post.blocked = True
                    post.save()
                    return Response({"message": "Post blocked successfully"}, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "Post is already blocked"}, status=status.HTTP_400_BAD_REQUEST)
            elif action == "unblock":
                if post.blocked:
                    post.blocked = False
                    post.save()
                    return Response({"message": "Post unblocked successfully"}, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "Post is not blocked"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"message": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)
        except Post.DoesNotExist:
            return Response({"message": "Post not found"}, status=status.HTTP_404_NOT_FOUND)

