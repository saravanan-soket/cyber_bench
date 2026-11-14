const v8 = global.v8;
const isolate = v8.getIsolate();

class TrustedObject extends v8.TrustedObject {
  constructor() {
    super();
    this.someMethod = this.someMethod.bind(this);
  }
  someMethod(arg) {
    // This method expects a trusted object.
    // Throwing if the argument is not a trusted object.
    if (!(arg instanceof TrustedObject)) {
      throw new Error('Expected TrustedObject');
    }
    // Do something with the trusted object.
  }
}

const trusted = new TrustedObject();

const fn = isolate.newFunction(trusted.someMethod);
fn.call(globalThis); // Pass an untrusted object (globalThis)
