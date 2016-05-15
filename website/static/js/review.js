$(document).ready(function(){
  $("#review").submit(function( event ) { 
    a=$("#alert").attr("value")
    event.preventDefault();
    sendData();
    return false;
  });
});

function sendData(){

    $.ajax('/product_page/review',
       {
       type: "POST",
       data: $("#review").serialize(), 
       }).done(function() {  
        alert("Your review is submitted");
        window.location.reload();
       })
       .fail(function(jqXHR,textStatus){
        alert("Request failed:"+textStatus);
       });
    }