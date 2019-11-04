const path = require('path');
const VueLoaderPlugin = require('vue-loader/lib/plugin');
const HappyPack = require('happypack');
const ForkTsCheckerWebpackPlugin = require('fork-ts-checker-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const webpack = require('webpack');

function srcPath(subdir) {
	return path.join(__dirname, "..", subdir);
}

module.exports = {
	entry: {
		main: './src/main.ts'
	},

	output: {
		filename: '[name].js',
		chunkFilename: '[name].js',
		publicPath: '/auth/static/',
		path: path.resolve(__dirname, '../dist'),
	},

	optimization: {
		splitChunks: {
			cacheGroups: {
				vendor: {
					chunks: 'initial',
					name: 'vendor',
					test: /node_modules|src\/lib\/node_modules/,
					enforce: true
				},
			}
		},
		runtimeChunk: true,
		noEmitOnErrors: true
	},

	resolve: {
		alias: {
			vue$: 'vue/dist/vue.esm.js',
			lib: srcPath('src/lib'),
			css: srcPath('src/css'),
			src: srcPath('src'),
			"~": srcPath('src')
		},
		extensions: ['.ts', '.vue', '.js', '.json', '.less']
	},

	module: {
		rules: [
			{
				test: /^(?!.*\.spec\.ts$).*\.ts$/,
				exclude: [
					/node_modules/,
					/src\/lib\/node_modules/,

				],
				loader: 'happypack/loader?id=ts'
			},
			{
				test: /\.vue$/,
				exclude: [
					/node_modules/,
					/src\/lib\/node_modules/
				],
				use: 'vue-loader'
			},
			{
				test: /\.css$/,
				use: [
					'vue-style-loader',
					'css-loader'
				]
			},
			{
				test: /\.less$/,
				exclude: [
					/node_modules/,
					/src\/lib\/node_modules/
				],
				use: [
					'vue-style-loader',
					'css-loader',
					'less-loader'
				]
			},
			{
				test: /\.(png|jpg|gif|svg)$/,
				loader: 'file-loader',
				options: {
					name: '[name].[ext]'
				}
			},
			{
				test: /\.(woff|ttf)$/,
				loader: 'url-loader',
				options: {
					limit: 50000,
					mimetype: 'application/font-woff',

					// Output below the fonts directory
					name: './fonts/[name].[ext]',

					// Tweak publicPath to fix CSS lookups to take
					// the directory into account.
					publicPath: '../',
				},
			}
		]
	},

	plugins: [
		new HtmlWebpackPlugin({
			template: './src/index.html',
			inject: true
		}),
		new CopyWebpackPlugin([
			{
				from: path.resolve(__dirname, '../static'),
				to: "",
				ignore: ['.*']
			}
		]),
		new ForkTsCheckerWebpackPlugin({
			checkSyntacticErrors: true,
			tslint: true,
			vue: true,
		}),
		new HappyPack({
			id: 'ts',
			threads: 4,
			loaders: [
				{
					loader: 'babel-loader',
				},
				{
					loader: 'ts-loader',
					options: {
						happyPackMode: true,
						appendTsSuffixTo: [/\.vue$/],
						experimentalWatchApi: true,
						transpileOnly: true,
					}
				}
			]
		}),
		new VueLoaderPlugin(),
		new webpack.NormalModuleReplacementPlugin(/element-ui[\/\\]lib[\/\\]locale[\/\\]lang[\/\\]zh-CN/, 'element-ui/lib/locale/lang/en')
	],
};
