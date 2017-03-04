$(document).ready(function(){
	console.log("hello")
	$(".ChangeVlan").click(function(){
  		var name = this.id
		$("#username").text("User: " + name)
		$("#inputname").attr("value", name)	
		$('.ui.modal').modal('show');
	});
	
});
