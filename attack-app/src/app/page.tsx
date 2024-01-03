import Image from 'next/image'
import Hero from './_components/Hero'
import TargetField from './_components/TargetField'
import AttackMenu from './_components/AttackMenu'

export default function Home() {
  return (
    <main className="bg-black w-screen items-center justify-between p-0">
      <div className="relative flex flex-col z-10 w-full items-center justify-between font-mono text-sm lg:flex">
        <Hero/>
      </div>
      <AttackMenu/>

    </main>
  )
}
