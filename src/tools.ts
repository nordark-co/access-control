import { GrantAttribute, FilteredResult } from "./types";

export function filterProperties<O, A extends Array<GrantAttribute>>(obj: O, attributes: A) {
    const workingCopy = {} as Record<string, any>;

    for (const key in obj) {
        if (attributes.includes(key)) workingCopy[key] = obj[key];
        if (attributes.includes('*')) workingCopy[key] = obj[key];
        if (attributes.includes(`!${key}`)) delete workingCopy[key];
    }

    return workingCopy as FilteredResult<O, A>;
}
