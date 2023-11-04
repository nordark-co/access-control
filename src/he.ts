
import { AccessController } from ".";

const controller = new AccessController();

const ac = controller.grant('user').readAny('video', {
    attributes: ['*', 'age', '!password']
});

ac.dumpGrants().user

const m = ac.getMetadata('user', 'video', 'read:any');

m.metadata?.attributes

ac.lock();
