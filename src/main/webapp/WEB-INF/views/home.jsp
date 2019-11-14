<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>  
 <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>  
 
 
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">  
<html>  
	<head>  
	<title>Home</title>  
	</head>  
	<body>  
		<h3> Hello ${userName}, </h3>  
		<a href="<c:url value='/logout'/>">Logout</a> 
		
		<h2>Add Events</h2>
		<div>
			<form name="f" action="events" method="POST">
			    <table>
			        <tr>
			            <td>Event ID:</td>
			            <td><input type='text' name='eventId' /></td>
			        </tr>
			        <tr>
			            <td>Event Name:</td>
			            <td><input type='text' name='eventName'></td>
			        </tr>
			        <tr>
			            <td colspan="2">&nbsp;</td>
			        </tr>
			        <tr>
			            <td colspan='2'><input name="submit" type="submit"></td>
			        </tr>
			    </table>
			</form>
		</div>
	</body>  
</html>  