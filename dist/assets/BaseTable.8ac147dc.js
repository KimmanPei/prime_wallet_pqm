import{B as e,D as a,L as l,E as t,r as d,o,e as n,f as s,g as r,w as i,i as u,t as c,p,j as m}from"./vendor.ef10c181.js";import{s as b}from"./request.6dc1c898.js";const f={name:"basetable",setup(){const d=e({address:"",name:"",pageIndex:1,pageSize:10}),o=a([]),n=a(0),s=()=>{console.log("get data"),(e=>(console.log("fetchdata"),b({url:"./table.json",method:"get",params:e})))(d).then((e=>{o.value=e.list,n.value=e.pageTotal||50}))};s();const r=a(!1);let i=e({name:"",address:""}),u=-1;return{query:d,tableData:o,pageTotal:n,editVisible:r,form:i,handleSearch:()=>{d.pageIndex=1,s()},handlePageChange:e=>{d.pageIndex=e,s()},handleDelete:e=>{l.confirm("确定要删除吗？","提示",{type:"warning"}).then((()=>{t.success("删除成功"),o.value.splice(e,1)})).catch((()=>{}))},handleEdit:(e,a)=>{u=e,Object.keys(i).forEach((e=>{i[e]=a[e]})),r.value=!0},saveEdit:()=>{r.value=!1,t.success(`修改第 ${u+1} 行成功`),Object.keys(i).forEach((e=>{o.value[u][e]=i[e]}))}}}},g={class:"crumbs"},h=(e=>(p("data-v-27442b90"),e=e(),m(),e))((()=>s("i",{class:"el-icon-lx-cascades"},null,-1))),y=u(" 基础表格 "),v={class:"container"},_={class:"handle-box"},V=u("搜索"),w=u("编辑 "),C=u("删除"),k={class:"pagination"},x={class:"dialog-footer"},q=u("取 消"),E=u("确 定");f.render=function(e,a,l,t,p,m){const b=d("el-breadcrumb-item"),f=d("el-breadcrumb"),j=d("el-option"),D=d("el-select"),I=d("el-input"),U=d("el-button"),z=d("el-table-column"),S=d("el-image"),T=d("el-tag"),$=d("el-table"),O=d("el-pagination"),P=d("el-form-item"),B=d("el-form"),L=d("el-dialog");return o(),n("div",null,[s("div",g,[r(f,{separator:"/"},{default:i((()=>[r(b,null,{default:i((()=>[h,y])),_:1})])),_:1})]),s("div",v,[s("div",_,[r(D,{modelValue:t.query.address,"onUpdate:modelValue":a[0]||(a[0]=e=>t.query.address=e),placeholder:"地址",class:"handle-select mr10"},{default:i((()=>[r(j,{key:"1",label:"广东省",value:"广东省"}),r(j,{key:"2",label:"湖南省",value:"湖南省"})])),_:1},8,["modelValue"]),r(I,{modelValue:t.query.name,"onUpdate:modelValue":a[1]||(a[1]=e=>t.query.name=e),placeholder:"用户名",class:"handle-input mr10"},null,8,["modelValue"]),r(U,{type:"primary",icon:"el-icon-search",onClick:t.handleSearch},{default:i((()=>[V])),_:1},8,["onClick"])]),r($,{data:t.tableData,border:"",class:"table",ref:"multipleTable","header-cell-class-name":"table-header"},{default:i((()=>[r(z,{prop:"id",label:"ID",width:"55",align:"center"}),r(z,{prop:"name",label:"用户名"}),r(z,{label:"账户余额"},{default:i((e=>[u("￥"+c(e.row.money),1)])),_:1}),r(z,{label:"头像(查看大图)",align:"center"},{default:i((e=>[r(S,{class:"table-td-thumb",src:e.row.thumb,"preview-src-list":[e.row.thumb]},null,8,["src","preview-src-list"])])),_:1}),r(z,{prop:"address",label:"地址"}),r(z,{label:"状态",align:"center"},{default:i((e=>[r(T,{type:"成功"===e.row.state?"success":"失败"===e.row.state?"danger":""},{default:i((()=>[u(c(e.row.state),1)])),_:2},1032,["type"])])),_:1}),r(z,{prop:"date",label:"注册时间"}),r(z,{label:"操作",width:"180",align:"center"},{default:i((e=>[r(U,{type:"text",icon:"el-icon-edit",onClick:a=>t.handleEdit(e.$index,e.row)},{default:i((()=>[w])),_:2},1032,["onClick"]),r(U,{type:"text",icon:"el-icon-delete",class:"red",onClick:a=>t.handleDelete(e.$index,e.row)},{default:i((()=>[C])),_:2},1032,["onClick"])])),_:1})])),_:1},8,["data"]),s("div",k,[r(O,{background:"",layout:"total, prev, pager, next","current-page":t.query.pageIndex,"page-size":t.query.pageSize,total:t.pageTotal,onCurrentChange:t.handlePageChange},null,8,["current-page","page-size","total","onCurrentChange"])])]),r(L,{title:"编辑",modelValue:t.editVisible,"onUpdate:modelValue":a[5]||(a[5]=e=>t.editVisible=e),width:"30%"},{footer:i((()=>[s("span",x,[r(U,{onClick:a[4]||(a[4]=e=>t.editVisible=!1)},{default:i((()=>[q])),_:1}),r(U,{type:"primary",onClick:t.saveEdit},{default:i((()=>[E])),_:1},8,["onClick"])])])),default:i((()=>[r(B,{"label-width":"70px"},{default:i((()=>[r(P,{label:"用户名"},{default:i((()=>[r(I,{modelValue:t.form.name,"onUpdate:modelValue":a[2]||(a[2]=e=>t.form.name=e)},null,8,["modelValue"])])),_:1}),r(P,{label:"地址"},{default:i((()=>[r(I,{modelValue:t.form.address,"onUpdate:modelValue":a[3]||(a[3]=e=>t.form.address=e)},null,8,["modelValue"])])),_:1})])),_:1})])),_:1},8,["modelValue"])])},f.__scopeId="data-v-27442b90";export default f;
