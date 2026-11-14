var a = new JS.Object();
var b = a.chunk();
var c = b.data;
a = null;
JS::GC::collect(JS::GC::Leave);
console.log(c.length);
