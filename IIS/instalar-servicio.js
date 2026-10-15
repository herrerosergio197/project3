/**
 * instalar-servicio.js
 * Registra el servidor como servicio de Windows para que arranque automáticamente
 *
 * Requisitos:
 *   npm install -g node-windows
 *   npm link node-windows
 *
 * Ejecutar como Administrador:
 *   node instalar-servicio.js
 */

const Service = require('node-windows').Service;
const path    = require('path');

const svc = new Service({
  name:        'SysLog Monitor',
  description: 'Servidor HTTPS para el visor de logs del sistema',
  script:      path.join(__dirname, 'server.js'),
  nodeOptions: [],
  env: [
    { name: 'NODE_ENV', value: 'production' }
  ]
});

svc.on('install', () => {
  svc.start();
  console.log('✅ Servicio instalado e iniciado correctamente.');
  console.log('   Puedes gestionarlo desde: services.msc');
  console.log('   Nombre del servicio: SysLog Monitor');
});

svc.on('alreadyinstalled', () => {
  console.log('ℹ️  El servicio ya estaba instalado. Para reinstalar:');
  console.log('   node desinstalar-servicio.js');
});

svc.on('error', (err) => {
  console.error('❌ Error al instalar el servicio:', err);
});

svc.install();
