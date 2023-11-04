import { Grants, GrantMetadata, GrantAction, FilteredResult, PermissionResult, GrantAttribute } from "./types";

export class AccessController<G extends Grants = Grants> {

    private _isLocked:boolean = false;

    constructor(private grants: G = {} as G) { }

    dumpGrants() {
        return this.grants
    }

    grant<E extends string>(role: E) {
        if (this._isLocked) throw new Error('AccessController is locked. You cannot modify grants after locking.');

        const addGrant = <A extends GrantAction, R extends string, M extends GrantMetadata>(action: A, resource: R, metadata?: M) => {
            // @ts-ignore
            if (!this.grants.hasOwnProperty(role)) this.grants[role] = {};
            if (!this.grants[role].hasOwnProperty(resource)) this.grants[role][resource] = {} as any;
            if (!this.grants[role][resource].hasOwnProperty(action)) this.grants[role][resource][action] = {};
            this.grants[role][resource][action] = metadata ?? { attributes: ['*'] };

            return this as unknown as AccessController<G & Record<E, Record<R, Record<A, M>>>>;
        }

        return {
            readOwn:<R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('read:own', resource, metadata);
            },
            readAny:<R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('read:any', resource, metadata);
            },
            createOwn:<R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('create:own', resource, metadata);
            },
            createAny:<R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('create:any', resource, metadata);
            },
            updateOwn:<R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('update:own', resource, metadata);
            },
            updateAny:<R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('update:any', resource, metadata);
            },
            deleteOwn:<R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('delete:own', resource, metadata);
            },
            deleteAny:<R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('delete:any', resource, metadata);
            }
        }

    }

    can(role: string) {

        const can = (action: GrantAction, resource: string) => {
            if (!this.grants.hasOwnProperty(role)) return false;
            if (!this.grants[role].hasOwnProperty(resource)) return false;
            if (!this.grants[role][resource].hasOwnProperty(action)) return false;
            return true;
        }

        return {
            readOwn(resource: string) {
                return can('read:own', resource);
            },
            readAny(resource: string) {
                return can('read:any', resource);
            },
            createOwn(resource: string) {
                return can('create:own', resource);
            },
            createAny(resource: string) {
                return can('create:any', resource);
            },
            updateOwn(resource: string) {
                return can('update:own', resource);
            },
            updateAny(resource: string) {
                return can('update:any', resource);
            },
            deleteOwn(resource: string) {
                return can('delete:own', resource);
            },
            deleteAny(resource: string) {
                return can('delete:any', resource);
            }
        }
    }

    getMetadata<E extends string, A extends GrantAction, R extends string>(role: E, resource: R, action: A) {
        const entityRole = this.grants?.[role];
        const entityResource = entityRole?.[resource];

        const metadata = entityResource?.[action];

        if (!metadata) return {
            granted: false,
            metadata: null
        } satisfies PermissionResult;

        return {
            granted: true,
            metadata: metadata as G[E][R][A]
        }
    }

    lock(){
        this._isLocked = true;
        return this;
    }
}
