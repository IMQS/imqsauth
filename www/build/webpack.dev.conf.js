const merge = require('webpack-merge');
const path = require('path')
const baseConfig = require('./webpack.base.conf.js');

module.exports = merge(baseConfig, {
	devtool: 'cheap-module-eval-source-map',

	output: {
		filename: '[name].js',
		path: path.resolve(__dirname, './dist'),
		devtoolModuleFilenameTemplate: info =>
			info.resourcePath.match(/\.vue$/) && !info.identifier.match(/type=script/)
				? `webpack-generated:///${info.resourcePath}?${info.hash}`
				: `original-code:///${info.resourcePath}`
		,
		devtoolFallbackModuleFilenameTemplate: 'webpack:///[resource-path]?[hash]',
		publicPath: '/auth'
	},

	devServer: {
		inline: true,
		clientLogLevel: 'warning',
		stats: {
			errorDetails: true,
			colors: true,
			modules: true,
			reasons: true,
		},
		port: 14000,
		proxy: {
			"/wws": {
				target: "http://localhost",
				ws: true,
				secure: false,
				changeOrigin: true,
			},
			"/jupiter/ws": {
				target: "http://localhost",
				ws: true,
				secure: false,
				changeOrigin: true,
			},
			"/": {
				target: "http://localhost",
				secure: false,
				changeOrigin: true,
			}
		},
		watchOptions: {
			ignored: /node_modules|src\/lib\/node_modules/
		},
		historyApiFallback: {
			index: '/auth/'
		},
		publicPath: "/auth",
		contentBase: path.resolve(__dirname, '../static')
	},

	module: {
		rules: [
		]
	},

	plugins: [
	]
});
