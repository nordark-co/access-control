import { Grants, GrantMetadata, GrantAction, PermissionResult, GrantMethods } from "./types";

type AccessDataMapperOptions = {
    onUpdate: (grants: Grants) => Promise<void>,
    onRead: () => Promise<Grants>,
    onError: (error: Error) => void
}
export class AccessDataMapper {
    private _isReading: boolean = false;
    private _grants?: Grants = undefined;
    private _readCallbacks: Array<(grants: Grants) => void> = [];

    constructor(private options: AccessDataMapperOptions) { }

    async read() {
        return new Promise<Grants>((resolve, reject) => {
            if (this._isReading) this._readCallbacks.push(resolve);
            else if (this._grants == undefined) {
                this._isReading = true;
                this.options.onRead().then(data => {
                    this._grants = data;
                    this._readCallbacks.forEach(cb => cb(data));
                    this._readCallbacks = [];
                    resolve(data);
                }).catch(error => {
                    this.options.onError(error);
                    reject(error);
                }).finally(() => {
                    this._isReading = false;
                });
            }
            else resolve(this._grants);
        })
    }

    async update(grants: Grants) {
        const oldGrants = structuredClone(grants);
        this._grants = grants;
        try {
            await this.options.onUpdate(grants);
            return true;
        }
        catch (error: Error | any) {
            this._grants = oldGrants;
            this.options.onError(error);
            return false;
        }
    }

}

type AccessUserMapperOptions<U> = {
    parseRoles: (user: U) => Array<string>,
    setRoles: (user: U, ...roles: Array<string>) => Promise<boolean>,
}
export class AccessUserMapper<U> {
    constructor(private options: AccessUserMapperOptions<U>) { }

    getRoles(user: U) {
        return this.options.parseRoles(user);
    }

    async setRoles(user: U, ...roles: Array<string>) {
        return this.options.setRoles(user, ...roles);
    }

}

type AccessControlOptions = {
    dataMapper?: AccessDataMapper
}

export class AccessControl {
    private _isLocked: boolean = false;
    private _grants?: Grants = undefined;

    protected constructor(private options?: AccessControlOptions) { }

    static async Init(options?: AccessControlOptions) {
        const ac = new AccessControl(options);
        ac._grants = (await options?.dataMapper?.read()) ?? [];
        return ac;
    }

    get grants() {
        return this._grants;
    }

    async commit(){
        if (!this.options?.dataMapper) return false;
        return this.options?.dataMapper?.update(this._grants!);
    }

    async refresh(){
        if (!this.options?.dataMapper) return false;
        this._grants = await this.options.dataMapper.read();
        return true;
    }

    grant<E extends string>(role: E) {
        if (this._isLocked) throw new Error('AccessController is locked. You cannot modify grants after locking.');

        const grantable:GrantMethods = {
            readOwn: <R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('read:own', resource, metadata);
            },
            readAny: <R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('read:any', resource, metadata);
            },
            createOwn: <R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('create:own', resource, metadata);
            },
            createAny: <R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('create:any', resource, metadata);
            },
            updateOwn: <R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('update:own', resource, metadata);
            },
            updateAny: <R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('update:any', resource, metadata);
            },
            deleteOwn: <R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('delete:own', resource, metadata);
            },
            deleteAny: <R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('delete:any', resource, metadata);
            },
            access: <R extends string, M extends GrantMetadata>(resource: R, metadata?: M) => {
                return addGrant('*:any', resource, metadata);
            },
        } as const;

        const addGrant = <A extends GrantAction, R extends string, M extends GrantMetadata>(action: A, resource: R, metadata?: M):GrantMethods => {
            const existingGrant = this._grants!.find(g => g.role == role && g.resource == resource);
            if (existingGrant) {
                const existingPolicy = existingGrant.policies.find(p => p.action == action);
                if (existingPolicy) existingPolicy.metadata = metadata ?? { attributes: ['*'] };
                else existingGrant.policies.push({ action, metadata: metadata ?? { attributes: ['*'] } });
            }
            else {
                this._grants!.push({
                    role,
                    resource,
                    policies: [{ action, metadata: metadata ?? { attributes: ['*'] } }]
                });
            }
            return grantable;
        }

        return grantable;

    }

    can(role: string) {

        const can = (action: GrantAction, resource: string):PermissionResult => {
            const grant = this._grants!.find(g => g.role == role && g.resource == resource);
            if (!grant) return { granted: false, metadata: null };
            const policy = grant.policies.find(p => {
                if (p.action === action) return true;
                if (p.action.endsWith(':any')) {
                    const [prefix] = p.action.split(':');
                    return action.startsWith(prefix);
                }
                if (p.action.startsWith('*')) {
                    const [, suffix] = p.action.split(':');
                    return action.endsWith(suffix);
                }
                return false;
            });
            if (!policy) return { granted: false, metadata: null };
            return { granted: true, metadata: policy.metadata };
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
            },
            access(resource: string) {
                return can('*:any', resource);
            }
        }
    }

    lock() {
        this._isLocked = true;
        return this;
    }

    async getRole(role: string) {
        const grants = this.options?.dataMapper ? await this.options.dataMapper.read() : (this._grants ?? []);
        return grants.filter(g => g.role == role);
    }

    async getPolicies(role: string, resource: string) {
        const grants = this.options?.dataMapper ? await this.options.dataMapper.read() : (this._grants ?? []);
        const grant = grants.find(g => g.role == role && g.resource == resource);
        return grant?.policies ?? [];
    }

    async getMetadata(role: string, resource: string, action: GrantAction) {
        const grants = this.options?.dataMapper ? await this.options.dataMapper.read() : (this._grants ?? []);
        const grant = grants.find(g => g.role == role && g.resource == resource);
        const policy = grant?.policies.find(p => p.action == action);
        return policy?.metadata ?? null;
    }

    async getAttributes(role: string, resource: string, action: GrantAction) {
        const grants = this.options?.dataMapper ? await this.options.dataMapper.read() : (this._grants ?? []);
        const grant = grants.find(g => g.role == role && g.resource == resource);
        const policy = grant?.policies.find(p => p.action == action);
        return policy?.metadata?.attributes ?? [];
    }
}

type UserAccessControlOptions<U> = {
    dataMapper?: AccessDataMapper,
    userMapper?: AccessUserMapper<U>
}

export class UserAccessControl<U> {
    private _grants?: Grants = undefined;

    private _localRoles: Map<U, Array<string>> = new Map();

    protected constructor(private options?: UserAccessControlOptions<U>) { }

    static async Init<U>(options?: UserAccessControlOptions<U>) {
        const uac = new UserAccessControl(options);
        uac._grants = (await options?.dataMapper?.read()) ?? [];
        return uac;
    }

    get grants() {
        return this._grants;
    }

    async refresh(){
        if (!this.options?.dataMapper) return false;
        this._grants = await this.options.dataMapper.read();
        return true;
    }

    async commit(){
        if (!this.options?.dataMapper) return false;
        return this.options.dataMapper.update(this._grants!);
    }

    can(user:U) {
        const roles = this.options?.userMapper ? this.options.userMapper.getRoles(user) : (this._localRoles.get(user) ?? []);
        const can = (action: GrantAction, resource: string):PermissionResult => {
            const grant = this._grants!.find(g => roles.includes(g.role) && g.resource == resource);
            if (!grant) return { granted: false, metadata: null };
            const policy = grant.policies.find(p => {
                if (p.action === action) return true;
                if (p.action.endsWith(':any')) {
                    const [prefix] = p.action.split(':');
                    return action.startsWith(prefix);
                }
                if (p.action.startsWith('*')) {
                    const [, suffix] = p.action.split(':');
                    return action.endsWith(suffix);
                }
                return false;
            });
            if (!policy) return { granted: false, metadata: null };
            return { granted: true, metadata: policy.metadata };
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
            },
            access(resource: string) {
                return can('*:any', resource);
            }
        }
    }

    async addRoles(user: U, ...roles: Array<string>) {
        if (!this.options?.userMapper) {
            const newRoles = Array.from( new Set([...(this._localRoles.get(user) ?? []), ...roles]) );
            this._localRoles.set(user, newRoles);
            return true;
        }
        const newRoles = Array.from( new Set([...this.options.userMapper.getRoles(user), ...roles]) );
        return this.options.userMapper.setRoles(user, ...newRoles);
    }

    async removeRoles(user: U, ...roles: Array<string>) {
        if (!this.options?.userMapper) {
            const newRoles = (this._localRoles.get(user) ?? []).filter(r => !roles.includes(r));
            this._localRoles.set(user, newRoles);
            return true;
        }
        const newRoles = this.options.userMapper.getRoles(user).filter(r => !roles.includes(r));
        return this.options.userMapper.setRoles(user, ...newRoles);
    }

    async getUserGrants(user:U) {
        if (!this.options?.userMapper) return [];
        if (!this.options?.dataMapper) return [];
        const roles = this.options.userMapper.getRoles(user);
        const grants = await this.options.dataMapper.read();
        return grants.filter(g => roles.includes(g.role));
    }

    async getPolicies(user: U, resource: string) {
        if (!this.options?.userMapper) return [];
        if (!this.options?.dataMapper) return [];
        const roles = this.options.userMapper.getRoles(user);
        const grants = await this.options.dataMapper.read();
        const grant = grants.find(g => roles.includes(g.role) && g.resource == resource);
        return grant?.policies ?? [];
    }

    async getMetadata(user: U, resource: string, action: GrantAction) {
        if (!this.options?.userMapper) return [];
        if (!this.options?.dataMapper) return [];
        const roles = this.options.userMapper.getRoles(user);
        const grants = await this.options.dataMapper.read();
        const grant = grants.find(g => roles.includes(g.role) && g.resource == resource);
        const policy = grant?.policies.find(p => p.action == action);
        return policy?.metadata ?? null;
    }

    async getAttributes(user: U, resource: string, action: GrantAction) {
        if (!this.options?.userMapper) return [];
        if (!this.options?.dataMapper) return [];
        const roles = this.options.userMapper.getRoles(user);
        const grants = await this.options.dataMapper.read();
        const grant = grants.find(g => roles.includes(g.role) && g.resource == resource);
        const policy = grant?.policies.find(p => p.action == action);
        return policy?.metadata?.attributes ?? [];
    }
}

