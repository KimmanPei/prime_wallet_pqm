import{_ as e}from"./cropper.234bceea.js";import{a}from"./index.24cc35e4.js";import{D as l,r as t,o as s,e as o,f as r,g as p,w as c,p as n,j as u,i}from"./vendor.ef10c181.js";const d={name:"upload",components:{VueCropper:e},setup(){const e=l(""),t=l(a),s=l(!1),o=l(null);return{cropper:o,imgSrc:e,cropImg:t,dialogVisible:s,setImage:a=>{const l=a.target.files[0];if(!l.type.includes("image/"))return;const t=new FileReader;t.onload=a=>{s.value=!0,e.value=a.target.result,o.value&&o.value.replace(a.target.result)},t.readAsDataURL(l)},cropImage:()=>{t.value=o.value.getCroppedCanvas().toDataURL()},cancelCrop:()=>{s.value=!1,t.value=a}}}},m=e=>(n("data-v-6d5bae33"),e=e(),u(),e),v={class:"crumbs"},g=m((()=>r("i",{class:"el-icon-lx-calendar"},null,-1))),f=i(" 表单 "),b=i("图片上传"),_={class:"container"},j=m((()=>r("div",{class:"content-title"},"支持拖拽",-1))),h=m((()=>r("div",{class:"plugins-tips"},[i(" Element UI自带上传组件。 访问地址： "),r("a",{href:"http://element.eleme.io/#/zh-CN/component/upload",target:"_blank"},"Element UI Upload")],-1))),I=m((()=>r("i",{class:"el-icon-upload"},null,-1))),C=m((()=>r("div",{class:"el-upload__text"},[i(" 将文件拖到此处，或 "),r("em",null,"点击上传")],-1))),U=m((()=>r("div",{class:"el-upload__tip"},"只能上传 jpg/png 文件，且不超过 500kb",-1))),k=m((()=>r("div",{class:"content-title"},"支持裁剪",-1))),x=m((()=>r("div",{class:"plugins-tips"},[i(" vue-cropperjs：一个封装了 cropperjs 的 Vue 组件。 访问地址： "),r("a",{href:"https://github.com/Agontuk/vue-cropperjs",target:"_blank"},"vue-cropperjs")],-1)));d.render=function(e,a,l,n,u,i){const d=t("el-breadcrumb-item"),m=t("el-breadcrumb"),D=t("el-upload");return s(),o("div",null,[r("div",v,[p(m,{separator:"/"},{default:c((()=>[p(d,null,{default:c((()=>[g,f])),_:1}),p(d,null,{default:c((()=>[b])),_:1})])),_:1})]),r("div",_,[j,h,p(D,{class:"upload-demo",drag:"",action:"http://jsonplaceholder.typicode.com/api/posts/",multiple:""},{tip:c((()=>[U])),default:c((()=>[I,C])),_:1}),k,x])])},d.__scopeId="data-v-6d5bae33";export default d;
