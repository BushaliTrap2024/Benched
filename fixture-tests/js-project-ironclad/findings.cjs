const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { test } = require('node:test');
const { parse } = require('acorn');

const appDir = resolve(process.env.IRONCLAD_APP_DIR || resolve(__dirname, '../../fixtures/js-project-ironclad/project'));

function source(file) {
  return parse(readFileSync(resolve(appDir, file), 'utf8'), {
    ecmaVersion: 'latest',
  });
}

function constantString(node) {
  if (node?.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }
  if (node?.type === 'BinaryExpression' && node.operator === '+') {
    const left = constantString(node.left);
    const right = constantString(node.right);
    if (left !== undefined && right !== undefined) return left + right;
  }
}

function transparentBlock(statement) {
  if (statement.type === 'IfStatement' && statement.test.type === 'Literal' &&
      statement.test.value === true && statement.consequent.type === 'BlockStatement') {
    return statement.consequent.body;
  }
  if (statement.type === 'TryStatement' && !statement.finalizer) {
    const handler = statement.handler;
    const [only, ...rest] = handler?.body.body ?? [];
    if (handler?.param?.type === 'Identifier' && rest.length === 0 &&
        only?.type === 'ThrowStatement' && only.argument.type === 'Identifier' &&
        only.argument.name === handler.param.name) {
      return statement.block.body;
    }
  }
}

function findStatement(body, predicate) {
  for (const statement of body) {
    if (predicate(statement)) return { statement, scope: body };
    const nested = transparentBlock(statement);
    const match = nested && findStatement(nested, predicate);
    if (match) return match;
  }
}

function property(object, name) {
  return object?.properties?.find(({ key }) =>
    key?.name === name || key?.value === name)?.value;
}

function binding(body, name) {
  return body.flatMap(statement => statement.declarations ?? [])
    .find(declaration => declaration.id.name === name)?.init;
}

function inconclusive(evidence) {
  assert.fail(`Inconclusive source check. ${evidence}`);
}

test('Knex configuration contains a password literal [js-hardcoded-creds-3]', () => {
  const { body } = source('app.js');
  const config = body.flatMap(statement => statement.declarations ?? [])
    .map(declaration => declaration.init)
    .find(node => node?.callee?.callee?.name === 'require' &&
      constantString(node.callee.arguments[0]) === 'knex')?.arguments[0];
  const password = property(property(config, 'connection'), 'password');
  const value = password?.type === 'Identifier' ? binding(body, password.name) : password;

  if (constantString(value) === undefined) {
    inconclusive('No password string literal resolved in the supported Knex configuration.');
  }
});

test('Lookup ID is interpolated into raw SQL [js-sql-injection-3]', () => {
  const route = source('app.js').body
    .map(statement => statement.expression)
    .find(node => node?.callee?.property?.name === 'get' &&
      constantString(node.arguments[0]) === '/users');
  const handler = route?.arguments[1];
  const request = handler?.params?.[0]?.name;
  const statements = handler?.body?.body ?? [];
  const match = findStatement(statements, statement => statement.type === 'ExpressionStatement');
  const lookup = match?.statement.expression?.callee?.object?.callee?.object;
  const id = lookup?.arguments?.[1];
  const input = id?.type === 'Identifier'
    ? binding(match.scope, id.name) ?? binding(statements, id.name)
    : id;
  const helper = source('userMode.js').body.find(node =>
    node.type === 'FunctionDeclaration' && node.id.name === lookup?.callee?.name);
  const query = helper && findStatement(helper.body.body, node => node.type === 'ReturnStatement')?.statement.argument;

  if (!request || input?.object?.object?.name !== request ||
      input.object.property?.name !== 'query' || input.property?.name !== 'id' ||
      query?.callee?.object?.name !== helper?.params[0]?.name ||
      query?.callee?.property?.name !== 'raw' ||
      !query.arguments[0]?.expressions?.some(node =>
        node.type === 'Identifier' && node.name === helper.params[1]?.name)) {
    inconclusive('The fixture-specific check could not establish the request-to-query flow.');
  }
});
