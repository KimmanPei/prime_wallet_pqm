import{k as e,D as a,E as r,r as t,o as s,e as n,f as c,g as i,w as d,i as o,t as l,p as m,j as f}from"./vendor.ef10c181.js";import{s as b}from"./request.6dc1c898.js";const p={name:"basetable",setup(){const t=e(),s=a([{id:1,transactionHash:"8b7e1f66afb6fc83ac678eb74d21348f81e270a570153559947069ae72f47066",sendAddress:"1CK6KHY6MHgYvmRQ4PAafKYDrg1ejbH1cE",receiveAddress:"1A32KFEX7JNPmU1PVjrtiXRrTQcesT3Nf1",amount:5678.9,time:"2021-12-27 10:32:38",confirm:10},{id:2,transactionHash:"12341f66afb6fc83ac678eb74d21348f81e270a570153559947069ae72f47066",sendAddress:"1CK6KHY6MHgYvmRQ4PAafKYDrg1ejbH1cE",receiveAddress:"1A32KFEX7JNPmU1PVjrtiXRrTQcesT3Nf1",amount:5678.9,time:"2021-12-27 10:32:38",confirm:10},{id:2,transactionHash:"56781f66afb6fc83ac678eb74d21348f81e270a570153559947069ae72f47066",sendAddress:"1CK6KHY6MHgYvmRQ4PAafKYDrg1ejbH1cE",receiveAddress:"1A32KFEX7JNPmU1PVjrtiXRrTQcesT3Nf1",amount:5678.9,time:"2021-12-27 10:32:38",confirm:10},{id:3,transactionHash:"90121f66afb6fc83ac678eb74d21348f81e270a570153559947069ae72f47066",sendAddress:"1CK6KHY6MHgYvmRQ4PAafKYDrg1ejbH1cE",receiveAddress:"1A32KFEX7JNPmU1PVjrtiXRrTQcesT3Nf1",amount:5678.9,time:"2021-12-27 10:32:38",confirm:10}]),n=()=>{var e;(e={coin:t.params.coin},console.log("get my transaction"),b({url:"./myTransaction/"+e.coin+".json",method:"get",params:e})).then((e=>{s.value=e})).catch((e=>{console.log(e),r.error("获取交易数据失败")}))};return n(),{formData:s,getMyTransactionData:n}},created(){this.$watch((()=>this.$route.params),((e,a)=>{this.$route.path.startsWith("/myTransaction")&&this.getMyTransactionData()}))}},u={class:"crumbs"},h=(e=>(m("data-v-3c681ef2"),e=e(),f(),e))((()=>c("i",{class:"el-icon-lx-cascades"},null,-1))),g={class:"container"};p.render=function(e,a,r,m,f,b){const p=t("el-breadcrumb-item"),A=t("el-breadcrumb"),v=t("el-table-column"),H=t("el-table");return s(),n("div",null,[c("div",u,[i(A,{separator:"/"},{default:d((()=>[i(p,null,{default:d((()=>[h,o(" 我的"+l(e.$route.params.coin)+"交易 ",1)])),_:1})])),_:1})]),c("div",g,[i(H,{data:m.formData,border:"",class:"table",ref:"multipleTable","header-cell-class-name":"table-header"},{default:d((()=>[i(v,{prop:"id",label:"ID","min-width":"2",align:"center"}),i(v,{prop:"transactionHash",label:"交易哈希","min-width":"6",align:"center"}),i(v,{prop:"sendAddress",label:"发送地址","min-width":"5",align:"center"}),i(v,{prop:"receiveAddress",label:"接收地址","min-width":"5",align:"center"}),i(v,{prop:"amount",label:"金额","min-width":"2",align:"center"}),i(v,{prop:"time",label:"交易时间","min-width":"5",align:"center"}),i(v,{prop:"confirm",label:"确认数","min-width":"2",align:"center"})])),_:1},8,["data"])])])},p.__scopeId="data-v-3c681ef2";export default p;
