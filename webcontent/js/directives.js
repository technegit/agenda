(function ($app) {
    var parseDateValue = function (modelValue) {
      var parts = modelValue.split("/");
      var dt = new Date(parseInt(parts[2], 10),
                        parseInt(parts[1], 10) - 1,
                        parseInt(parts[0], 10));
      return dt;
    }
    
    var parseDatetimeValue = function (modelValue) {
      var parts = modelValue.split(" ");
      var date = parts[0];
      date = date.split("/");
      var time = parts[1];
      time = time.split(":");
      var dt = new Date(parseInt(date[2], 10),
                        parseInt(date[1], 10) - 1,
                        parseInt(date[0], 10));
      dt.setHours(time[0]);
      dt.setMinutes(time[1]);
      return dt;
    }
    
    app.directive('asDate', function () {
        return {
            require: '^ngModel',
            restrict: 'A',
            link: function (scope, element, attrs, ctrl) {
                element.datepicker({
                  format: 'dd/mm/yyyy',                
                  language: 'pt-BR',
                  todayBtn: "linked",
                  autoclose: true
                });
                
                element.on('show', function(e){
                  var el = $(this);
                  var currDate = parseDateValue(el.val());
                  el.data({date: currDate}).datepicker('update').children("input").val(currDate);
                });
                
                ctrl.$formatters.splice(0, ctrl.$formatters.length);
                ctrl.$parsers.splice(0, ctrl.$parsers.length);
                ctrl.$formatters.push(function (modelValue) {
                  alert(modelValue);
                    if (!modelValue) {
                        return;
                    }
                    var data = new Date(modelValue);
                    var dia = data.getDate();
                    if (dia.toString().length == 1)
                      dia = "0"+dia;
                    var mes = data.getMonth()+1;
                    if (mes.toString().length == 1)
                      mes = "0"+mes;
                    var ano = data.getFullYear();  
                    return dia+"/"+mes+"/"+ano;
                });
                ctrl.$parsers.push(parseDateValue);
            }
        };
    })
    
    .directive('asDatetime', function () {
        return {
            require: '^ngModel',
            restrict: 'A',
            link: function (scope, element, attrs, ctrl) {
                element.datepicker({
                  format: 'dd/mm/yyyy',                
                  language: 'pt-BR',
                  todayBtn: "linked",
                  autoclose: true
                });
                
                element.on('show', function(e){
                  var el = $(this);
                  var currDate = parseDateValue(el.val());
                  el.data({date: currDate}).datepicker('update').children("input").val(currDate);
                });
                
                ctrl.$formatters.splice(0, ctrl.$formatters.length);
                ctrl.$parsers.splice(0, ctrl.$parsers.length);
                ctrl.$formatters.push(function (modelValue) {
                    if (!modelValue) {
                        return;
                    }
                    var data = new Date(modelValue);
                    var dia = data.getDate();
                    if (dia.toString().length == 1)
                      dia = "0"+dia;
                    var mes = data.getMonth()+1;
                    if (mes.toString().length == 1)
                      mes = "0"+mes;
                    var ano = data.getFullYear();  
                    var horas = data.getHours();
                    if (horas.toString().length == 1)
                      horas = "0"+horas;
                    var minutos = data.getMinutes();
                    if (minutos.toString().length == 1)
                      minutos = "0"+minutos;
                    return dia+"/"+mes+"/"+ano+" "+horas+":"+minutos;
                });
                ctrl.$parsers.push(parseDatetimeValue);
            }
        };
    })
	
	.directive('pwCheck', [function () { 'use strict';
		return {
		  require: 'ngModel',
		  link: function (scope, elem, attrs, ctrl) {
			var firstPassword = '#' + attrs.pwCheck;
			elem.add(firstPassword).on('keyup', function () {
			  scope.$apply(function () {
				var v = elem.val()===$(firstPassword).val();
				ctrl.$setValidity('pwmatch', v);
			  });
			});
		  }
		}
	}])
} (app));
  