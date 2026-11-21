import React, { useEffect } from 'react';
import Layout from './components/Layout';
import { useRoute } from './router';
import { findRoute } from './routes';

export default function App() {
  const path = useRoute();
  const route = findRoute(path);
  useEffect(() => { document.title = `${route.label} – TAK Server Admin`; }, [route]);
  const Page = route.element;
  return (
    <Layout route={route}>
      <Page key={route.path} />
    </Layout>
  );
}
