import{k as e,D as a,B as s,E as d,L as t,r as n,o as l,e as c,f as r,g as i,w as o,i as p,t as u,p as m,j as h}from"./vendor.ef10c181.js";import{s as f}from"./request.6dc1c898.js";import{r as b}from"./index.24cc35e4.js";const g={name:"basetable",setup(){const n=e();a(!1),s({name:"",address:""});const l=a([{id:1,address:"bc1qppsntrhcfe8m48dszxzjq9tfdd4ccpua0hqej2",balance:1234.5,usdBalance:5678.9},{id:2,address:"021qppsntrhcfe8m48dszxzjq9tfdd4ccpua0hqej2",balance:1234.5,usdBalance:5678.9},{id:3,address:"031qppsntrhcfe8m48dszxzjq9tfdd4ccpua0hqej2",balance:1234.5,usdBalance:5678.9},{id:4,address:"041qppsntrhcfe8m48dszxzjq9tfdd4ccpua0hqej2",balance:12.5,usdBalance:5718}]),c=()=>{var e;(e={coin:n.params.coin},console.log("get address"),f({url:"./address/"+e.coin+".json",method:"get",params:e})).then((e=>{l.value=e})).catch((e=>{console.log(e),d.error("获取地址数据失败")}))};return c(),{formData:l,handleDelete:e=>{t.confirm("确定要删除吗？","提示",{type:"warning"}).then((()=>{d.success("删除功能还没有实现")})).catch((()=>{}))},handleSend:(e,a)=>{b.push({name:"transfer",params:{coin:n.params.coin,address:a.address}})},handleAddAddress:()=>{d.warning("添加地址功能还没有实现"),c()},getAddressData:c}},created(){this.$watch((()=>this.$route.params),((e,a)=>{this.$route.path.startsWith("/address")&&this.getAddressData()}))}},j={class:"crumbs"},q=(e=>(m("data-v-55c3dcf5"),e=e(),h(),e))((()=>r("i",{class:"el-icon-lx-cascades"},null,-1))),x={class:"container"},w={class:"handle-box"},v=p("添加地址"),_=p("发送 "),z=p("删除");g.render=function(e,a,s,d,t,m){const h=n("el-breadcrumb-item"),f=n("el-breadcrumb"),b=n("el-button"),g=n("el-table-column"),D=n("el-table");return l(),c("div",null,[r("div",j,[i(f,{separator:"/"},{default:o((()=>[i(h,null,{default:o((()=>[q,p(" 我的"+u(e.$route.params.coin)+"地址 ",1)])),_:1})])),_:1})]),r("div",x,[r("div",w,[i(b,{type:"primary",icon:"el-icon-plus",onClick:d.handleAddAddress},{default:o((()=>[v])),_:1},8,["onClick"])]),i(D,{data:d.formData,border:"",class:"table",ref:"multipleTable","header-cell-class-name":"table-header"},{default:o((()=>[i(g,{prop:"id",label:"ID","min-width":"5",align:"center"}),i(g,{prop:"address",label:"地址","min-width":"20",align:"center"}),i(g,{prop:"balance",label:"余额","min-width":"10",align:"center"}),i(g,{prop:"usdBalance",label:"美元","min-width":"10",align:"center"}),i(g,{label:"操作","min-width":"10",align:"center"},{default:o((e=>[i(b,{type:"text",icon:"el-icon-edit",onClick:a=>d.handleSend(e.$index,e.row)},{default:o((()=>[_])),_:2},1032,["onClick"]),i(b,{type:"text",icon:"el-icon-delete",class:"red",onClick:a=>d.handleDelete(e.$index,e.row)},{default:o((()=>[z])),_:2},1032,["onClick"])])),_:1})])),_:1},8,["data"])])])},g.__scopeId="data-v-55c3dcf5";export default g;