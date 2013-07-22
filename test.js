var libdtrace = require('./index.js')

function buffhandler() {
  console.log("buffhandler", arguments);
}

var handle = libdtrace.Consumer(buffhandler);

console.log("we have consumer", handle);

var prog = 'BEGIN { trace("hello world"); }';

libdtrace.strcompile(handle, prog);
libdtrace.go(handle);

libdtrace.consume(handle, function (probe, rec) {
  gc();
  console.log("in consume");
  if (rec)
    console.log(rec.data);
});
gc();
