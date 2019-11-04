import { getQueryParam } from 'lib/base/uri';

export function redirectToQueryParam(): void {
	const redirect = getQueryParam("redirect");
	window.location.href = redirect ? redirect : "";
}
