

export type GrantActionType = 'own' | 'any';
export type GrantAction = `create:${GrantActionType}` | `read:${GrantActionType}` | `update:${GrantActionType}` | `delete:${GrantActionType}` | `*:${GrantActionType}`;
export type GrantAttribute = `*` | `!${string}` | (string & {});
export type GrantMetadata = {
    attributes?: Array<GrantAttribute>;
}
export type GrantPolicy = {
    action: GrantAction,
    metadata: GrantMetadata
}

export type Grant = {
    role: string,
    resource: string,
    policies: Array<GrantPolicy>
}

export type Grants = Array<Grant>;

export type GrantMethods = {
    readOwn: (resource: string, metadata?: GrantMetadata) => GrantMethods,
    readAny: (resource: string, metadata?: GrantMetadata) => GrantMethods,
    createOwn: (resource: string, metadata?: GrantMetadata) => GrantMethods,
    createAny: (resource: string, metadata?: GrantMetadata) => GrantMethods,
    updateOwn: (resource: string, metadata?: GrantMetadata) => GrantMethods,
    updateAny: (resource: string, metadata?: GrantMetadata) => GrantMethods,
    deleteOwn: (resource: string, metadata?: GrantMetadata) => GrantMethods,
    deleteAny: (resource: string, metadata?: GrantMetadata) => GrantMethods,
    access: (resource: string, metadata?: GrantMetadata) => GrantMethods
};

export type PermissionResult<M extends GrantMetadata = GrantMetadata> = {
    granted: false,
    metadata?: null
} | {
    granted: true,
    metadata: M
};


// @internal DO NOT USE
export const GrantSymbol: unique symbol = Symbol('Grant');

export type FilteredResult<O, A extends ReadonlyArray<GrantAttribute>> = {
    [GrantSymbol]: A;
} & O;