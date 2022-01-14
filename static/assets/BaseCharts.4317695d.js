import{_ as t}from"./vue-schart.084077bf.js";import{r as a,o as s,e as l,f as e,g as o,w as i,p as n,j as c,i as r}from"./vendor.ef10c181.js";const b={name:"basecharts",components:{Schart:t},setup:()=>({options1:{type:"bar",title:{text:"最近一周各品类销售图"},bgColor:"#fbfbfb",labels:["周一","周二","周三","周四","周五"],datasets:[{label:"家电",fillColor:"rgba(241, 49, 74, 0.5)",data:[234,278,270,190,230]},{label:"百货",data:[164,178,190,135,160]},{label:"食品",data:[144,198,150,235,120]}]},options2:{type:"line",title:{text:"最近几个月各品类销售趋势图"},bgColor:"#fbfbfb",labels:["6月","7月","8月","9月","10月"],datasets:[{label:"家电",data:[234,278,270,190,230]},{label:"百货",data:[164,178,150,135,160]},{label:"食品",data:[114,138,200,235,190]}]},options3:{type:"pie",title:{text:"服装品类销售饼状图"},legend:{position:"left"},bgColor:"#fbfbfb",labels:["T恤","牛仔裤","连衣裙","毛衣","七分裤","短裙","羽绒服"],datasets:[{data:[334,278,190,235,260,200,141]}]},options4:{type:"ring",title:{text:"环形三等分"},showValue:!1,legend:{position:"bottom",bottom:40},bgColor:"#fbfbfb",labels:["vue","react","angular"],datasets:[{data:[500,500,500]}]}})},d=t=>(n("data-v-42b77b5a"),t=t(),c(),t),p={class:"crumbs"},u=d((()=>e("i",{class:"el-icon-pie-chart"},null,-1))),v=r(" schart图表 "),f={class:"container"},h=d((()=>e("div",{class:"plugins-tips"},[r(" vue-schart：vue.js封装sChart.js的图表组件。 访问地址： "),e("a",{href:"https://github.com/lin-xin/vue-schart",target:"_blank"},"vue-schart")],-1))),g={class:"schart-box"},m=d((()=>e("div",{class:"content-title"},"柱状图",-1))),x={class:"schart-box"},C=d((()=>e("div",{class:"content-title"},"折线图",-1))),_={class:"schart-box"},j=d((()=>e("div",{class:"content-title"},"饼状图",-1))),I={class:"schart-box"},y=d((()=>e("div",{class:"content-title"},"环形图",-1)));b.render=function(t,n,c,r,b,d){const w=a("el-breadcrumb-item"),k=a("el-breadcrumb"),S=a("schart");return s(),l("div",null,[e("div",p,[o(k,{separator:"/"},{default:i((()=>[o(w,null,{default:i((()=>[u,v])),_:1})])),_:1})]),e("div",f,[h,e("div",g,[m,o(S,{class:"schart",canvasId:"bar",options:r.options1},null,8,["options"])]),e("div",x,[C,o(S,{class:"schart",canvasId:"line",options:r.options2},null,8,["options"])]),e("div",_,[j,o(S,{class:"schart",canvasId:"pie",options:r.options3},null,8,["options"])]),e("div",I,[y,o(S,{class:"schart",canvasId:"ring",options:r.options4},null,8,["options"])])])])},b.__scopeId="data-v-42b77b5a";export default b;