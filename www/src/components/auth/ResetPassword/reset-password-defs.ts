// Password validation
export function isValidPasswordOption(password: string): boolean {
	let passwordIsValid = true;
	if (!/[a-z]/.test(password)) passwordIsValid = false;
	if (!/[A-Z]/.test(password)) passwordIsValid = false;
	if (!/\d/.test(password)) passwordIsValid = false;
	if (!/(?=(.*[!"#$%&'()*+,./:;<=>?@\^_`{|}~\-]){2,})/.test(password)) passwordIsValid = false;
	if (!/^(?!.*([\da-zA-Z!"#$%&'()*+,./:;<=>?@\^_`{|}~\-])\1{2,}).+$/.test(password)) passwordIsValid = false;
	if (password.length < 8) passwordIsValid = false;
	return passwordIsValid;
}


export function hasConsecutiveCharacters(password: any): boolean {
	// Check for sequential numerical characters
	for (const i in password)
		if (/\d/.test(String.fromCharCode(password.charCodeAt(i))) && +password[+i + 1] == +password[i] + 1 && +password[+i + 2] == +password[i] + 2) return true;

	// Check for sequential alphabetical characters
	for (const i in password)
		if (/[a-zA-Z]/.test(String.fromCharCode(password.charCodeAt(i))) && String.fromCharCode(password.charCodeAt(i) + 1) == password[+i + 1] && String.fromCharCode(password.charCodeAt(i) + 2) == password[+i + 2]) return true;

	return false;
}


// Estimated score out of a hundred for password strength
// TODO:	replace this with https://github.com/dropbox/zxcvbn or some other calculator from
// http://users.encs.concordia.ca/~mmannan/publications/password-meters-tissec.pdf
export function passwordStrength(password: string): number {
	// Checks a string for a list of characters
	const countContain = function (pw, strCheck) {
		let nCount = 0;
		for (let i = 0; i < pw.length; i++) {
			if (strCheck.indexOf(pw.charAt(i)) > -1) {
				nCount++;
			}
		}
		return nCount;
	};

	let nScore = 0;
	if (password.length === 0) return 0;

	// Length
	nScore += password.length * 5;

	// Letters
	// bonus points for not just lowercase or just uppercase
	if (
		!(
			password === password.toLowerCase() ||
			password === password.toUpperCase()
		)
	) {
		nScore += 20;
	}

	// Numbers and other characters
	const normalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const nNormalCount = countContain(password, normalChars);
	const nOtherCount = password.length - nNormalCount;
	nScore += Math.min(7 * nOtherCount, 21);

	return Math.min(nScore, 100);
}
