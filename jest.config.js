module.exports = {
  testEnvironment: 'jsdom',
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
