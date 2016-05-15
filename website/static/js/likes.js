$(document).ready(function(){
	var i=0;
	$("#likes").click(function(){
    	i+=1;
    	$("#likes").attr("value",i);
      // alert($("#likes").attr("value"))

    });
});
