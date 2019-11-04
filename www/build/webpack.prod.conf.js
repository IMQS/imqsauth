const merge = require('webpack-merge');
const baseConfig = require('./webpack.base.conf.js');

module.exports = merge(baseConfig, {
	devtool: 'source-map',

	module: {
		rules: [
		]
	},

	plugins: [
	],
});
