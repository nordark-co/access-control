

export type GrantActionType = 'own' | 'any';
export type GrantAction = `create:${GrantActionType}` | `read:${GrantActionType}` | `update:${GrantActionType}` | `delete:${GrantActionType}` | `*:${GrantActionType}`;
export type GrantAttribute = `*` | `!${string}` | (string & {});
export type GrantMetadata = {
    attributes?: Array<GrantAttribute>;
}

export type Grants = {
    [role:string] : {
        [resource: string]: Partial<Record<GrantAction, GrantMetadata>>
    }
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