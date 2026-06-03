module.exports = {
  testEnvironment: './jest.environment.js',
  testEnvironmentOptions: {
    customExportConditions: ['node', 'require', 'default'],
    url: 'https://localhost',
  },
  moduleNameMapper: {
    '^node-rsa$': '<rootDir>/node_modules/node-rsa/dist/index.node.cjs',
  },
  setupFiles: ['./jest.setup.js'],
  testMatch: ['**/test/**/*.js'],
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/windowSfet.js'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['html', 'text', 'json-summary', 'lcov'],
  coveragePathIgnorePatterns: [
    '/node_modules/'
  ]
};
